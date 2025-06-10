use crate::{encrypt_data, pad_message, receive_and_fetch_messages, send_encrypted_message};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
    time::Duration,
};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use eframe::egui::{self, Color32, TextureHandle};
use egui::{RichText, Ui};

fn encode_file_to_base64(path: &PathBuf) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| STANDARD.encode(&bytes))
}

#[derive(Clone)]
pub struct MessagingApp {
    pub username: String,
    pub shared_hybrid_secret: Arc<String>,
    pub shared_room_id: Arc<Mutex<String>>,
    pub shared_url: Arc<Mutex<String>>,
    pub messages: Arc<Mutex<VecDeque<String>>>,
}

impl MessagingApp {
    pub fn new(
        username: String,
        shared_hybrid_secret: Arc<String>,
        shared_room_id: Arc<Mutex<String>>,
        shared_url: Arc<Mutex<String>>,
    ) -> Self {
        Self {
            username,
            shared_hybrid_secret,
            shared_room_id,
            shared_url,
            messages: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
        }
    }
}

pub fn run_gui(app: MessagingApp) -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Amnezichat",
        native_options,
        Box::new(|cc| Box::new(EguiApp::new(app, cc))),
    )
}

struct EguiApp {
    input: String,
    sender: std::sync::mpsc::Sender<String>,
    messages: Arc<Mutex<VecDeque<String>>>,
    background_color: Color32,
    background_texture: Option<TextureHandle>,
    wallpaper_path: Option<PathBuf>,
    show_settings: bool,
    visible_batch_size: usize,
    selected_pfp_base64: Option<String>,
    selected_media_base64: Option<String>,
}

impl EguiApp {
    fn new(app: MessagingApp, _cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel::<String>();
        let send_app = app.clone();
        let send_messages = Arc::clone(&app.messages);

        thread::spawn(move || {
            for input_msg in rx {
                let formatted = format!("<strong>{}</strong>: {}", send_app.username, input_msg);
                let padded = pad_message(&formatted, 2048);
                let room_id = send_app.shared_room_id.lock().unwrap().clone();
                let url = send_app.shared_url.lock().unwrap().clone();
                let secret = &*send_app.shared_hybrid_secret;

                if let Ok(encrypted) = encrypt_data(&padded, secret) {
                    if send_encrypted_message(&encrypted, &room_id, &url).is_ok() {
                        let mut msgs = send_messages.lock().unwrap();
                        msgs.push_back(formatted);
                        if msgs.len() > 1000 {
                            msgs.pop_front();
                        }
                    }
                }
            }
        });

        let messages_thread = Arc::clone(&app.messages);
        let app_clone = app.clone();
        thread::spawn(move || loop {
            let room_id = app_clone.shared_room_id.lock().unwrap().clone();
            let url = app_clone.shared_url.lock().unwrap().clone();
            let secret = &*app_clone.shared_hybrid_secret;

            if let Ok(new_msgs) = receive_and_fetch_messages(&room_id, secret, &url, true) {
                let mut msgs = messages_thread.lock().unwrap();
                for msg in new_msgs {
                    if !msgs.contains(&msg) {
                        msgs.push_back(msg);
                        if msgs.len() > 1000 {
                            msgs.pop_front();
                        }
                    }
                }
            }

            thread::sleep(Duration::from_secs(10));
        });

        Self {
            input: String::new(),
            sender: tx,
            messages: Arc::clone(&app.messages),
            background_color: Color32::from_rgb(30, 30, 30),
            background_texture: None,
            wallpaper_path: None,
            show_settings: false,
            visible_batch_size: 50,
            selected_pfp_base64: None,
            selected_media_base64: None,
        }
    }

    fn load_wallpaper(&mut self, ctx: &egui::Context, path: &PathBuf) {
        if let Ok(image) = image::open(path) {
            let size = [image.width() as usize, image.height() as usize];
            let image_buffer = image.to_rgba8();
            let pixels = image_buffer.as_flat_samples();
            let texture = ctx.load_texture(
                "custom_wallpaper",
                egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice()),
                egui::TextureOptions::LINEAR,
            );
            self.background_texture = Some(texture);
            self.wallpaper_path = Some(path.clone());
        }
    }
}

impl eframe::App for EguiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::default());

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("\u{2699} Settings").clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
        });

        if self.show_settings {
            egui::Window::new("Settings")
                .collapsible(true)
                .default_size((320.0, 200.0))
                .show(ctx, |ui| {
                    ui.label("Background Color:");
                    ui.color_edit_button_srgba(&mut self.background_color);

                    if ui.button("Choose Custom Wallpaper").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Image", &["png", "jpg", "jpeg", "bmp"])
                            .pick_file()
                        {
                            self.load_wallpaper(ctx, &path);
                        }
                    }

                    if ui.button("Clear Wallpaper").clicked() {
                        self.background_texture = None;
                        self.wallpaper_path = None;
                    }

                    ui.separator();
                    ui.label("Profile Picture:");
                    if ui.button("Select Profile Picture").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Image", &["png", "jpg", "jpeg", "bmp"])
                            .pick_file()
                        {
                            self.selected_pfp_base64 = encode_file_to_base64(&path);
                        }
                    }

                    if self.selected_pfp_base64.is_some() {
                        ui.label("Profile picture selected.");
                    } else {
                        ui.label("No profile picture selected.");
                    }
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(self.background_color))
            .show(ctx, |ui| {
                if let Some(bg) = &self.background_texture {
                    let rect = ui.min_rect();
                    ui.painter().rect_filled(rect, 0.0, self.background_color);
                    ui.painter().image(
                        bg.id(),
                        rect,
                        egui::Rect::from_min_max(
                            egui::Pos2::ZERO,
                            egui::Pos2::new(1.0, 1.0),
                        ),
                        Color32::WHITE,
                    );
                }

                let messages_guard = self.messages.lock().unwrap();
                let total_messages = messages_guard.len();
                let visible_start = total_messages.saturating_sub(self.visible_batch_size);
                let visible_messages: Vec<_> = messages_guard
                    .iter()
                    .skip(visible_start)
                    .cloned()
                    .collect();

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .max_height(ui.available_height() - 80.0)
                    .show(ui, |ui| {
                        for msg in visible_messages {
                            ui.add_space(6.0);
                            let panel_color = ui.visuals().panel_fill;
                            let transparent_panel_color = Color32::from_rgba_premultiplied(
                                panel_color.r(),
                                panel_color.g(),
                                panel_color.b(),
                                200,
                            );

                            egui::Frame::group(ui.style())
                                .fill(transparent_panel_color)
                                .rounding(egui::Rounding::same(8.0))
                                .inner_margin(egui::vec2(8.0, 4.0))
                                .show(ui, |ui| {
                                    parse_html_message_with_widgets(ui, &msg, ctx);
                                });
                        }

                        ui.add_space(80.0);
                    });
            });

        egui::TopBottomPanel::bottom("bottom_panel")
            .resizable(false)
            .default_height(90.0)
            .show(ctx, |ui| {
                ui.separator();
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    if ui.button("\u{1F5BC} Image").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Image", &["png", "jpg", "jpeg", "bmp"])
                            .pick_file()
                        {
                            self.selected_media_base64 = encode_file_to_base64(&path);
                        }
                    }
                });

                ui.horizontal(|ui| {
                    let available_width = ui.available_width() - 100.0;

                    let text_edit = ui.add_sized(
                        [available_width, 36.0],
                        egui::TextEdit::singleline(&mut self.input)
                            .hint_text("Type your message...")
                            .margin(egui::vec2(10.0, 6.0))
                            .frame(true)
                            .font(egui::FontId::proportional(14.0)),
                    );

                    let send_clicked = ui
                        .add_sized(
                            [90.0, 36.0],
                            egui::Button::new(
                                egui::RichText::new("Send").text_style(egui::TextStyle::Button),
                            )
                            .fill(ui.visuals().selection.bg_fill),
                        )
                        .clicked();

                    let enter_pressed =
                        text_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                    if send_clicked || enter_pressed {
                        let trimmed = self.input.trim();
                        if !trimmed.is_empty() {
                            let mut composed = trimmed.to_string();

                            if let Some(pfp) = &self.selected_pfp_base64 {
                                composed.push_str(&format!(" <pfp>{}</pfp>", pfp));
                            }
                            if let Some(media) = self.selected_media_base64.take() {
                                composed.push_str(&format!(" <media>{}</media>", media));
                            }

                            if composed.eq_ignore_ascii_case("exit") {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            } else {
                                let _ = self.sender.send(composed);
                            }
                            self.input.clear();
                        }
                    }
                });

                ui.add_space(8.0);
            });
    }
}

fn decode_base64_to_image(ctx: &egui::Context, tag: &str, b64: &str) -> Option<TextureHandle> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let image = image::load_from_memory(&bytes).ok()?.to_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.as_flat_samples();
    Some(ctx.load_texture(
        format!("{}_image", tag),
        egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice()),
        egui::TextureOptions::LINEAR,
    ))
}

fn parse_html_message_with_widgets(ui: &mut Ui, msg: &str, ctx: &egui::Context) {
    let mut remaining = msg.to_string();

    if let (Some(start), Some(end)) = (remaining.find("<strong>"), remaining.find("</strong>")) {
        if end > start {
            let bold_text = &remaining[start + 8..end];
            ui.label(RichText::new(bold_text).strong());
            remaining = remaining[end + 9..].to_string();
    
            if remaining.starts_with(": ") {
                remaining = remaining[2..].to_string();
            } else if remaining.starts_with(':') {
                remaining = remaining[1..].to_string();
            }
        }
    }    

    let max_pfp_size = egui::Vec2::new(32.0, 32.0);
    let max_media_size = egui::Vec2::new(400.0, 300.0);

    while let Some(start) = remaining.find('<') {
        if let Some(end) = remaining[start..].find('>') {
            let end = start + end;
            let tag = &remaining[start + 1..end];
            let close_tag = format!("</{}>", tag);
            if let Some(close_start) = remaining[end + 1..].find(&close_tag) {
                let content_start = end + 1;
                let content_end = end + 1 + close_start;
                let content = &remaining[content_start..content_end];

                match tag {
                    "media" | "pfp" => {
                        if let Some(tex) = decode_base64_to_image(ctx, tag, content) {
                            let size = tex.size_vec2();
                            let max_size = if tag == "pfp" { max_pfp_size } else { max_media_size };
                            let scale = (max_size.x / size.x).min(max_size.y / size.y).min(1.0);
                            let scaled_size = size * scale;
                            let (rect, _) = ui.allocate_exact_size(scaled_size, egui::Sense::hover());
                            ui.painter().image(tex.id(), rect, egui::Rect::from_min_max(egui::Pos2::ZERO, egui::Pos2::new(1.0, 1.0)), Color32::WHITE);
                        }
                    }
                    _ => {}
                }

                remaining.replace_range(start..(content_end + close_tag.len()), "");
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if !remaining.trim().is_empty() {
        ui.label(RichText::new(remaining.trim()).monospace());
    }
}

use crate::{encrypt_data, pad_message, receive_and_fetch_messages, send_encrypted_message};
use std::{
    path::PathBuf,
    sync::{mpsc::channel, Arc, Mutex},
    thread,
    time::Duration,
};

use eframe::egui;
use egui::{Color32, TextureHandle};

#[derive(Clone)]
pub struct MessagingApp {
    pub username: String,
    pub shared_hybrid_secret: Arc<String>,
    pub shared_room_id: Arc<Mutex<String>>,
    pub shared_url: Arc<Mutex<String>>,
    pub messages: Arc<Mutex<Vec<String>>>,
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
            messages: Arc::new(Mutex::new(Vec::new())),
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
    messages: Arc<Mutex<Vec<String>>>,
    background_color: Color32,
    background_texture: Option<TextureHandle>,
    wallpaper_path: Option<PathBuf>,
    show_settings: bool,
    visible_start: usize,
    visible_batch_size: usize,
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
                        msgs.push(formatted);
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
                        msgs.push(msg);
                    }
                }

                const MAX_CACHE_SIZE: usize = 1000;
                if msgs.len() > MAX_CACHE_SIZE {
                    let drain_count = msgs.len() - MAX_CACHE_SIZE;
                    msgs.drain(0..drain_count);
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
            visible_start: 0,
            visible_batch_size: 50,
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
                .default_size((320.0, 160.0))
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

                let messages = self.messages.lock().unwrap().clone();
                let total_messages = messages.len();
                let visible_end = total_messages;
                let visible_start = self.visible_start.min(visible_end);
                let visible_messages = &messages[visible_start..visible_end];

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
                                    ui.label(
                                        parse_html_message(msg)
                                            .font(egui::FontId::monospace(15.0)),
                                    );
                                });
                        }

                        ui.add_space(80.0);
                    });
            });

        egui::TopBottomPanel::bottom("bottom_panel")
            .resizable(false)
            .default_height(60.0)
            .show(ctx, |ui| {
                ui.separator();
                ui.add_space(6.0);

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
                            if trimmed.eq_ignore_ascii_case("exit") {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            } else {
                                let _ = self.sender.send(trimmed.to_string());
                                let total = self.messages.lock().unwrap().len();
                                self.visible_start = total.saturating_sub(self.visible_batch_size);
                            }
                            self.input.clear();
                        }
                    }
                });

                ui.add_space(8.0);
            });
    }
}

fn parse_html_message(msg: &str) -> egui::RichText {
    let mut cleaned_msg = msg.to_string();

    for tag in &["media", "audio", "pfp"] {
        while let Some(start) = cleaned_msg.find(&format!("<{}>", tag)) {
            if let Some(end) = cleaned_msg[start..].find(&format!("</{}>", tag)) {
                let end = start + end + tag.len() + 3;
                cleaned_msg.replace_range(start..end, "");
            } else {
                break;
            }
        }
    }

    if let (Some(start), Some(end)) = (cleaned_msg.find("<strong>"), cleaned_msg.find("</strong>")) {
        if end > start + 8 {
            let bold_text = &cleaned_msg[start + 8..end];
            let rest = &cleaned_msg[end + 9..];
            return egui::RichText::new(format!("{}{}", bold_text, rest)).strong();
        }
    }

    egui::RichText::new(cleaned_msg)
}

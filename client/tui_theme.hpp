#pragma once

#ifdef TORRENT_ENABLE_FTXUI

#include <ftxui/dom/elements.hpp>

#include <string>
#include <utility>

struct CatppuccinMocha {
    const ftxui::Color base = ftxui::Color::RGB(30, 30, 46);
    const ftxui::Color mantle = ftxui::Color::RGB(24, 24, 37);
    const ftxui::Color crust = ftxui::Color::RGB(17, 17, 27);
    const ftxui::Color text = ftxui::Color::RGB(205, 214, 244);
    const ftxui::Color subtext = ftxui::Color::RGB(166, 173, 200);
    const ftxui::Color overlay = ftxui::Color::RGB(108, 112, 134);
    const ftxui::Color surface0 = ftxui::Color::RGB(49, 50, 68);
    const ftxui::Color surface1 = ftxui::Color::RGB(69, 71, 90);
    const ftxui::Color blue = ftxui::Color::RGB(137, 180, 250);
    const ftxui::Color lavender = ftxui::Color::RGB(180, 190, 254);
    const ftxui::Color mauve = ftxui::Color::RGB(203, 166, 247);
    const ftxui::Color green = ftxui::Color::RGB(166, 227, 161);
    const ftxui::Color yellow = ftxui::Color::RGB(249, 226, 175);
    const ftxui::Color peach = ftxui::Color::RGB(250, 179, 135);
    const ftxui::Color red = ftxui::Color::RGB(243, 139, 168);
    const ftxui::Color teal = ftxui::Color::RGB(148, 226, 213);
};

inline const CatppuccinMocha &catppuccinMocha() {
    static const CatppuccinMocha palette;
    return palette;
}

inline ftxui::Element themedPanel(const std::string &title,
                                  ftxui::Element content,
                                  const ftxui::Color &background) {
    using namespace ftxui;
    const CatppuccinMocha &mocha = catppuccinMocha();
    return window(text(title) | bold | color(mocha.lavender),
                  std::move(content) | color(mocha.text) |
                      bgcolor(background)) |
           color(mocha.surface0) | bgcolor(background);
}

#endif

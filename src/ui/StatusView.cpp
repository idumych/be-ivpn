/*
 * IVPN for Vitruvian - connection status header.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "StatusView.h"

#include <algorithm>
#include <cmath>

#include <ControlLook.h>
#include <Font.h>


static const rgb_color kGreen = {46, 160, 67, 255};
static const rgb_color kAmber = {222, 152, 20, 255};
static const rgb_color kRed = {200, 55, 55, 255};


StatusView::StatusView()
	:
	BView("status", B_WILL_DRAW | B_FULL_UPDATE_ON_RESIZE),
	fLevel(kUnprotected),
	fHeadline("Not connected"),
	fDetail("")
{
	SetViewUIColor(B_PANEL_BACKGROUND_COLOR);
}


void
StatusView::SetStatus(Level level, const char* headline, const char* detail)
{
	if (fLevel == level && fHeadline == headline && fDetail == detail)
		return;
	fLevel = level;
	fHeadline = headline;
	fDetail = detail;
	Invalidate();
}


float
StatusView::_LampSize() const
{
	font_height fh;
	be_bold_font->GetHeight(&fh);
	return ceilf((fh.ascent + fh.descent) * 1.6f) * 2;
}


BSize
StatusView::MinSize()
{
	font_height plain;
	be_plain_font->GetHeight(&plain);
	float lamp = _LampSize();
	float spacing = be_control_look->DefaultItemSpacing();
	float textHeight = (plain.ascent + plain.descent) * 3.4f;
	return BSize(lamp + spacing * 3 + be_plain_font->StringWidth("M") * 22,
		std::max(lamp, textHeight) + spacing * 2);
}


BSize
StatusView::PreferredSize()
{
	BSize size = MinSize();
	size.width = std::max(size.width, be_plain_font->StringWidth("M") * 30);
	return size;
}


void
StatusView::Draw(BRect /*updateRect*/)
{
	BRect bounds = Bounds();
	float spacing = be_control_look->DefaultItemSpacing();
	float lamp = _LampSize();

	rgb_color color = fLevel == kProtected ? kGreen
		: (fLevel == kWorking ? kAmber : kRed);

	// status lamp: outer soft ring + solid core
	BRect lampRect(spacing, (bounds.Height() - lamp) / 2,
		spacing + lamp, (bounds.Height() + lamp) / 2);
	SetDrawingMode(B_OP_ALPHA);
	rgb_color halo = color;
	halo.alpha = 60;
	SetHighColor(halo);
	FillEllipse(lampRect);
	SetDrawingMode(B_OP_COPY);
	BRect core = lampRect.InsetByCopy(lamp * 0.2f, lamp * 0.2f);
	SetHighColor(color);
	FillEllipse(core);

	// a check mark / bar / cross inside the lamp
	SetHighColor(255, 255, 255);
	SetPenSize(std::max(2.0f, lamp / 14));
	BPoint c((core.left + core.right) / 2, (core.top + core.bottom) / 2);
	float r = core.Width() / 4;
	if (fLevel == kProtected) {
		StrokeLine(BPoint(c.x - r, c.y), BPoint(c.x - r / 3, c.y + r * 0.7f));
		StrokeLine(BPoint(c.x - r / 3, c.y + r * 0.7f),
			BPoint(c.x + r, c.y - r * 0.6f));
	} else if (fLevel == kWorking) {
		StrokeLine(BPoint(c.x - r, c.y), BPoint(c.x + r, c.y));
	} else {
		StrokeLine(BPoint(c.x - r * 0.7f, c.y - r * 0.7f),
			BPoint(c.x + r * 0.7f, c.y + r * 0.7f));
		StrokeLine(BPoint(c.x - r * 0.7f, c.y + r * 0.7f),
			BPoint(c.x + r * 0.7f, c.y - r * 0.7f));
	}
	SetPenSize(1);

	// text
	float x = lampRect.right + spacing * 1.5f;
	BFont headline(be_bold_font);
	headline.SetSize(be_bold_font->Size() * 1.4f);
	font_height hfh, pfh;
	headline.GetHeight(&hfh);
	be_plain_font->GetHeight(&pfh);

	float textBlock = hfh.ascent + hfh.descent + spacing / 2
		+ pfh.ascent + pfh.descent;
	float y = (bounds.Height() - textBlock) / 2 + hfh.ascent;

	SetHighUIColor(B_PANEL_TEXT_COLOR);
	SetFont(&headline);
	BString text = fHeadline;
	headline.TruncateString(&text, B_TRUNCATE_END, bounds.right - x - spacing);
	DrawString(text.String(), BPoint(x, y));

	y += hfh.descent + spacing / 2 + pfh.ascent;
	SetFont(be_plain_font);
	SetHighUIColor(B_PANEL_TEXT_COLOR, B_LIGHTEN_1_TINT);
	text = fDetail;
	be_plain_font->TruncateString(&text, B_TRUNCATE_END,
		bounds.right - x - spacing);
	DrawString(text.String(), BPoint(x, y));
}

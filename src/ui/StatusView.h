/*
 * Be IVPN - the header showing whether the connection is
 * protected: a coloured status lamp, a headline and a detail line.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_STATUS_VIEW_H
#define IVPN_STATUS_VIEW_H

#include <String.h>
#include <View.h>

class StatusView : public BView {
public:
	enum Level {
		kUnprotected,
		kWorking,
		kProtected,
	};

							StatusView();

	void					SetStatus(Level level, const char* headline,
								const char* detail);

	virtual void			Draw(BRect updateRect);
	virtual BSize			MinSize();
	virtual BSize			PreferredSize();

private:
	float					_LampSize() const;
	int32					_WrapDetail(float width, BString lines[2]) const;

	Level					fLevel;
	BString					fHeadline;
	BString					fDetail;
};

#endif	// IVPN_STATUS_VIEW_H

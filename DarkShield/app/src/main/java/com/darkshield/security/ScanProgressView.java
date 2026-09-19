package com.darkshield.security;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

/**
 * Lightweight, dependency-free circular progress indicator for long scans.
 * The percentage is visual only; the scanner remains the source of truth.
 */
public final class ScanProgressView extends View {
    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint progressPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF arc = new RectF();
    private int percent;

    public ScanProgressView(Context context, AttributeSet attrs) {
        super(context, attrs);
        trackPaint.setStyle(Paint.Style.STROKE);
        trackPaint.setStrokeWidth(dp(8));
        trackPaint.setColor(0xFF252B38);
        trackPaint.setStrokeCap(Paint.Cap.ROUND);

        progressPaint.setStyle(Paint.Style.STROKE);
        progressPaint.setStrokeWidth(dp(8));
        progressPaint.setColor(0xFF66E3A4);
        progressPaint.setStrokeCap(Paint.Cap.ROUND);

        textPaint.setTextAlign(Paint.Align.CENTER);
        textPaint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        textPaint.setColor(0xFFFFFFFF);
        textPaint.setTextSize(dp(24));
        setContentDescription("Progresso da verificação: 0 por cento");
    }

    public void setPercent(int value) {
        percent = Math.max(0, Math.min(100, value));
        setContentDescription("Progresso da verificação: " + percent + " por cento");
        invalidate();
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float size = Math.min(getWidth(), getHeight());
        float left = (getWidth() - size) / 2f + dp(8);
        float top = (getHeight() - size) / 2f + dp(8);
        float right = left + size - dp(16);
        float bottom = top + size - dp(16);
        arc.set(left, top, right, bottom);
        float start = -90f;
        canvas.drawArc(arc, start, 360f, false, trackPaint);
        canvas.drawArc(arc, start, percent * 3.6f, false, progressPaint);

        Paint.FontMetrics metrics = textPaint.getFontMetrics();
        float baseline = getHeight() / 2f - (metrics.ascent + metrics.descent) / 2f;
        canvas.drawText(percent + "%", getWidth() / 2f, baseline, textPaint);
    }

    private float dp(float value) {
        return value * getResources().getDisplayMetrics().density;
    }
}

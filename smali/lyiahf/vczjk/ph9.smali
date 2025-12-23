.class public final Llyiahf/vczjk/ph9;
.super Llyiahf/vczjk/vt6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0O0:Landroid/content/Context;

.field public final synthetic OooO0OO:Landroid/text/TextPaint;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/vt6;

.field public final synthetic OooO0o0:Llyiahf/vczjk/qh9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qh9;Landroid/content/Context;Landroid/text/TextPaint;Llyiahf/vczjk/vt6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ph9;->OooO0o0:Llyiahf/vczjk/qh9;

    iput-object p2, p0, Llyiahf/vczjk/ph9;->OooO0O0:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/ph9;->OooO0OO:Landroid/text/TextPaint;

    iput-object p4, p0, Llyiahf/vczjk/ph9;->OooO0Oo:Llyiahf/vczjk/vt6;

    return-void
.end method


# virtual methods
.method public final OooOoOO(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ph9;->OooO0Oo:Llyiahf/vczjk/vt6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vt6;->OooOoOO(I)V

    return-void
.end method

.method public final OooOoo0(Landroid/graphics/Typeface;Z)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ph9;->OooO0OO:Landroid/text/TextPaint;

    iget-object v1, p0, Llyiahf/vczjk/ph9;->OooO0o0:Llyiahf/vczjk/qh9;

    iget-object v2, p0, Llyiahf/vczjk/ph9;->OooO0O0:Landroid/content/Context;

    invoke-virtual {v1, v2, v0, p1}, Llyiahf/vczjk/qh9;->OooO0o(Landroid/content/Context;Landroid/text/TextPaint;Landroid/graphics/Typeface;)V

    iget-object v0, p0, Llyiahf/vczjk/ph9;->OooO0Oo:Llyiahf/vczjk/vt6;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/vt6;->OooOoo0(Landroid/graphics/Typeface;Z)V

    return-void
.end method

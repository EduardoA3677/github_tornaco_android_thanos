.class public final Llyiahf/vczjk/lp1;
.super Llyiahf/vczjk/o00O00o0;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/lp1;->OooO00o:Ljava/util/ArrayList;

    return-void
.end method

.method public static OooOO0O(Llyiahf/vczjk/ld9;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/gd0;)V
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p0}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/iy8;

    iget-object v2, v1, Llyiahf/vczjk/iy8;->OooOOO0:Ljava/lang/StringBuilder;

    const/16 v3, 0xa0

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    const/16 v4, 0xa

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v4, p0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/wc5;

    iget-object v4, v4, Llyiahf/vczjk/wc5;->OooO0OO:Llyiahf/vczjk/up3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->length()I

    move-result v4

    invoke-virtual {v1, v4, p2}, Llyiahf/vczjk/iy8;->OooO0O0(ILjava/lang/CharSequence;)V

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/iy8;->OooO00o(C)V

    sget-object p2, Llyiahf/vczjk/t51;->OooO0oO:Llyiahf/vczjk/ja7;

    iget-object v1, p0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/pi4;

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    invoke-virtual {p0, p3, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    invoke-virtual {p0, p3}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/dv1;)V
    .locals 1

    invoke-virtual {p1}, Landroid/widget/TextView;->getMovementMethod()Landroid/text/method/MovementMethod;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {}, Landroid/text/method/LinkMovementMethod;->getInstance()Landroid/text/method/MovementMethod;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setMovementMethod(Landroid/text/method/MovementMethod;)V

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/dv1;Landroid/text/SpannableStringBuilder;)V
    .locals 8

    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const-class v1, Llyiahf/vczjk/jf6;

    const/4 v2, 0x0

    invoke-interface {p2, v2, v0, v1}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/jf6;

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v1

    array-length v3, v0

    move v4, v2

    :goto_0
    if-ge v4, v3, :cond_0

    aget-object v5, v0, v4

    iget-object v6, v5, Llyiahf/vczjk/jf6;->OooOOO:Ljava/lang/String;

    invoke-virtual {v1, v6}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    move-result v6

    const/high16 v7, 0x3f000000    # 0.5f

    add-float/2addr v6, v7

    float-to-int v6, v6

    iput v6, v5, Llyiahf/vczjk/jf6;->OooOOOo:I

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const-class v1, Llyiahf/vczjk/yn9;

    invoke-interface {p2, v2, v0, v1}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/yn9;

    if-eqz v0, :cond_1

    array-length v1, v0

    move v3, v2

    :goto_1
    if-ge v3, v1, :cond_1

    aget-object v4, v0, v3

    invoke-interface {p2, v4}, Landroid/text/Spannable;->removeSpan(Ljava/lang/Object;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    new-instance v0, Llyiahf/vczjk/yn9;

    invoke-direct {v0, p1}, Llyiahf/vczjk/yn9;-><init>(Llyiahf/vczjk/dv1;)V

    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    move-result p1

    const/16 v1, 0x12

    invoke-interface {p2, v0, v2, p1, v1}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/tg7;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/qd0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/qd0;

    const/16 v2, 0x9

    invoke-direct {v1, v2}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v2, Llyiahf/vczjk/j79;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v1, Llyiahf/vczjk/qd0;

    const/4 v2, 0x3

    invoke-direct {v1, v2}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v2, Llyiahf/vczjk/lm2;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v1, Llyiahf/vczjk/qd0;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v2, Llyiahf/vczjk/md0;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v1, Llyiahf/vczjk/qd0;

    const/4 v2, 0x2

    invoke-direct {v1, v2}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v2, Llyiahf/vczjk/s01;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    const-class v1, Llyiahf/vczjk/zw2;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    const-class v1, Llyiahf/vczjk/sw3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v0, Llyiahf/vczjk/qd0;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/c15;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v0, Llyiahf/vczjk/qd0;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/wm3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v0, Llyiahf/vczjk/qd0;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/b05;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    new-instance v0, Llyiahf/vczjk/qd0;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/cq9;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    return-void
.end method

.method public final OooOO0(Llyiahf/vczjk/tqa;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/lp3;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/lp3;-><init>(Llyiahf/vczjk/o00O00o0;I)V

    const-class v1, Llyiahf/vczjk/bh9;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/j79;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/lm2;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0x9

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/md0;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xa

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/s01;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/zw2;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xc

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/sw3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xd

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/ju3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xf

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/nk0;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xf

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/if6;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/c15;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/cq9;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/wm3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/cx8;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/km3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/ao6;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/b05;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    return-void
.end method

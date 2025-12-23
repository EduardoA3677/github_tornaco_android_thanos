.class public final Llyiahf/vczjk/pc5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $defaultColor:J

.field final synthetic $disableLinkMovementMethod:Z

.field final synthetic $markdown:Ljava/lang/String;

.field final synthetic $markdownRender:Llyiahf/vczjk/vc5;

.field final synthetic $maxLines:I

.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $style:Llyiahf/vczjk/rn9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vc5;Ljava/lang/String;ZLlyiahf/vczjk/oe3;ILlyiahf/vczjk/rn9;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc5;->$markdownRender:Llyiahf/vczjk/vc5;

    iput-object p2, p0, Llyiahf/vczjk/pc5;->$markdown:Ljava/lang/String;

    iput-boolean p3, p0, Llyiahf/vczjk/pc5;->$disableLinkMovementMethod:Z

    iput-object p4, p0, Llyiahf/vczjk/pc5;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput p5, p0, Llyiahf/vczjk/pc5;->$maxLines:I

    iput-object p6, p0, Llyiahf/vczjk/pc5;->$style:Llyiahf/vczjk/rn9;

    iput-wide p7, p0, Llyiahf/vczjk/pc5;->$defaultColor:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/dv1;

    const-string v0, "textView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pc5;->$style:Llyiahf/vczjk/rn9;

    iget-wide v1, p0, Llyiahf/vczjk/pc5;->$defaultColor:J

    invoke-virtual {v0}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v3

    sget-wide v5, Llyiahf/vczjk/n21;->OooOO0:J

    cmp-long v5, v3, v5

    if-eqz v5, :cond_0

    move-wide v1, v3

    goto :goto_0

    :cond_0
    new-instance v3, Llyiahf/vczjk/n21;

    :goto_0
    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v1

    invoke-virtual {p1, v1}, Landroid/widget/TextView;->setTextColor(I)V

    iget-object v1, v0, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-wide v2, v1, Llyiahf/vczjk/dy8;->OooO0O0:J

    invoke-static {v2, v3}, Llyiahf/vczjk/un9;->OooO0OO(J)F

    move-result v2

    const/4 v3, 0x2

    invoke-virtual {p1, v3, v2}, Landroidx/appcompat/widget/AppCompatTextView;->setTextSize(IF)V

    iget-object v0, v0, Llyiahf/vczjk/rn9;->OooO0O0:Llyiahf/vczjk/ho6;

    iget-wide v4, v0, Llyiahf/vczjk/ho6;->OooO0OO:J

    const-wide v6, 0xff00000000L

    and-long/2addr v6, v4

    const-wide v8, 0x100000000L

    cmp-long v2, v6, v8

    if-nez v2, :cond_1

    invoke-static {v4, v5}, Llyiahf/vczjk/un9;->OooO0OO(J)F

    move-result v2

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v4

    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v4

    invoke-static {v3, v2, v4}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    move-result v2

    float-to-int v2, v2

    invoke-static {p1, v2}, Llyiahf/vczjk/tp6;->Oooo0O0(Landroid/widget/TextView;I)V

    :cond_1
    sget-object v2, Llyiahf/vczjk/vh9;->OooO0Oo:Llyiahf/vczjk/vh9;

    iget-object v4, v1, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    invoke-static {v4, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    const/16 v2, 0x10

    invoke-virtual {p1, v2}, Landroid/widget/TextView;->setPaintFlags(I)V

    :cond_2
    const/4 v2, 0x1

    iget v0, v0, Llyiahf/vczjk/ho6;->OooO00o:I

    const v4, 0x800003

    if-ne v0, v2, :cond_3

    goto :goto_2

    :cond_3
    const/4 v5, 0x5

    if-ne v0, v5, :cond_4

    goto :goto_2

    :cond_4
    if-ne v0, v3, :cond_5

    goto :goto_1

    :cond_5
    const/4 v5, 0x6

    if-ne v0, v5, :cond_6

    :goto_1
    const v4, 0x800005

    goto :goto_2

    :cond_6
    const/4 v5, 0x3

    if-ne v0, v5, :cond_7

    move v4, v2

    :cond_7
    :goto_2
    invoke-virtual {p1, v4}, Landroid/widget/TextView;->setGravity(I)V

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1d

    if-lt v4, v5, :cond_8

    const/4 v5, 0x4

    if-ne v0, v5, :cond_8

    invoke-static {p1}, Llyiahf/vczjk/xb8;->OooOo(Llyiahf/vczjk/dv1;)V

    :cond_8
    iget-object v0, v1, Llyiahf/vczjk/dy8;->OooO0Oo:Llyiahf/vczjk/cb3;

    const/4 v5, 0x0

    if-eqz v0, :cond_a

    iget v0, v0, Llyiahf/vczjk/cb3;->OooO00o:I

    if-ne v0, v2, :cond_9

    goto :goto_3

    :cond_9
    move v3, v5

    :goto_3
    invoke-virtual {p1}, Landroid/widget/TextView;->getTypeface()Landroid/graphics/Typeface;

    move-result-object v0

    invoke-virtual {p1, v0, v3}, Landroidx/appcompat/widget/AppCompatTextView;->setTypeface(Landroid/graphics/Typeface;I)V

    :cond_a
    iget-object v0, v1, Llyiahf/vczjk/dy8;->OooO0OO:Llyiahf/vczjk/ib3;

    if-eqz v0, :cond_e

    const/16 v3, 0x1c

    if-lt v4, v3, :cond_b

    invoke-virtual {p1}, Landroid/widget/TextView;->getTypeface()Landroid/graphics/Typeface;

    move-result-object v2

    iget v0, v0, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v2, v0}, Llyiahf/vczjk/md9;->OooO0OO(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;)V

    goto :goto_6

    :cond_b
    sget-object v3, Llyiahf/vczjk/ib3;->OooOo0o:Llyiahf/vczjk/ib3;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ib3;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_c

    move v3, v2

    goto :goto_4

    :cond_c
    sget-object v3, Llyiahf/vczjk/ib3;->OooOo0O:Llyiahf/vczjk/ib3;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ib3;->equals(Ljava/lang/Object;)Z

    move-result v3

    :goto_4
    if-eqz v3, :cond_d

    goto :goto_5

    :cond_d
    sget-object v2, Llyiahf/vczjk/ib3;->OooOo0:Llyiahf/vczjk/ib3;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ib3;->equals(Ljava/lang/Object;)Z

    move-result v2

    :goto_5
    invoke-virtual {p1}, Landroid/widget/TextView;->getTypeface()Landroid/graphics/Typeface;

    move-result-object v0

    invoke-virtual {p1, v0, v2}, Landroidx/appcompat/widget/AppCompatTextView;->setTypeface(Landroid/graphics/Typeface;I)V

    :cond_e
    :goto_6
    iget-object v0, v1, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    if-eqz v0, :cond_f

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "getContext(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOo00(Landroid/content/Context;)Llyiahf/vczjk/ea3;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    const v3, 0xffff

    invoke-virtual {v1, v0, v2, v5, v3}, Llyiahf/vczjk/ea3;->OooO0O0(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;II)Llyiahf/vczjk/i6a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/graphics/Typeface;

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;)V

    :cond_f
    iget-object v0, p0, Llyiahf/vczjk/pc5;->$markdownRender:Llyiahf/vczjk/vc5;

    iget-object v1, p0, Llyiahf/vczjk/pc5;->$markdown:Ljava/lang/String;

    check-cast v0, Llyiahf/vczjk/ad5;

    iget-object v2, v0, Llyiahf/vczjk/ad5;->OooO0OO:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_7
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_10

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_7

    :cond_10
    iget-object v3, v0, Llyiahf/vczjk/ad5;->OooO00o:Llyiahf/vczjk/ld9;

    if-eqz v1, :cond_21

    new-instance v4, Llyiahf/vczjk/md2;

    iget-object v6, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Ljava/util/ArrayList;

    iget-object v7, v3, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Ljava/util/ArrayList;

    iget-object v8, v3, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/ws7;

    invoke-direct {v4, v6, v8, v7}, Llyiahf/vczjk/md2;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/ws7;Ljava/util/ArrayList;)V

    :cond_11
    :goto_8
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v6

    move v7, v5

    :goto_9
    const/4 v8, -0x1

    const/16 v9, 0xd

    const/16 v10, 0xa

    if-ge v7, v6, :cond_12

    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    move-result v11

    if-eq v11, v10, :cond_13

    if-eq v11, v9, :cond_13

    add-int/lit8 v7, v7, 0x1

    goto :goto_9

    :cond_12
    move v7, v8

    :cond_13
    if-eq v7, v8, :cond_14

    invoke-virtual {v1, v5, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Llyiahf/vczjk/md2;->OooO(Ljava/lang/String;)V

    add-int/lit8 v5, v7, 0x1

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v6

    if-ge v5, v6, :cond_11

    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    move-result v6

    if-ne v6, v9, :cond_11

    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    move-result v6

    if-ne v6, v10, :cond_11

    add-int/lit8 v7, v7, 0x2

    move v5, v7

    goto :goto_8

    :cond_14
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v6

    if-lez v6, :cond_16

    if-eqz v5, :cond_15

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v6

    if-ge v5, v6, :cond_16

    :cond_15
    invoke-virtual {v1, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Llyiahf/vczjk/md2;->OooO(Ljava/lang/String;)V

    :cond_16
    iget-object v5, v4, Llyiahf/vczjk/md2;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/md2;->OooO0o(Ljava/util/ArrayList;)V

    new-instance v5, Llyiahf/vczjk/n62;

    iget-object v6, v4, Llyiahf/vczjk/md2;->OooOOO0:Ljava/util/LinkedHashMap;

    iget-object v7, v4, Llyiahf/vczjk/md2;->OooOO0O:Ljava/util/ArrayList;

    const/16 v8, 0x10

    const/4 v9, 0x0

    invoke-direct {v5, v8, v7, v6, v9}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    iget-object v6, v4, Llyiahf/vczjk/md2;->OooOO0:Llyiahf/vczjk/ws7;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v6, Llyiahf/vczjk/xz3;

    invoke-direct {v6, v5}, Llyiahf/vczjk/xz3;-><init>(Llyiahf/vczjk/n62;)V

    iget-object v5, v4, Llyiahf/vczjk/md2;->OooOOOO:Ljava/util/LinkedHashSet;

    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_a
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_17

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/o0OOO0o;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/o0OOO0o;->OooO0oO(Llyiahf/vczjk/xz3;)V

    goto :goto_a

    :cond_17
    iget-object v4, v4, Llyiahf/vczjk/md2;->OooOO0o:Llyiahf/vczjk/fd2;

    iget-object v4, v4, Llyiahf/vczjk/fd2;->OooO0O0:Llyiahf/vczjk/gd0;

    check-cast v4, Llyiahf/vczjk/ed2;

    iget-object v3, v3, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v3, Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_b
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_18

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/og9;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v5, Llyiahf/vczjk/ng9;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v5, v4}, Llyiahf/vczjk/dn8;->OooOooO(Llyiahf/vczjk/ed2;)V

    goto :goto_b

    :cond_18
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_19

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v5}, Llyiahf/vczjk/o00O00o0;->OooO0OO()V

    goto :goto_c

    :cond_19
    iget-object v0, v0, Llyiahf/vczjk/ad5;->OooO0O0:Llyiahf/vczjk/era;

    new-instance v7, Llyiahf/vczjk/pi4;

    const/4 v3, 0x1

    invoke-direct {v7, v3}, Llyiahf/vczjk/pi4;-><init>(I)V

    iget-object v3, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/tqa;

    new-instance v10, Llyiahf/vczjk/tp3;

    const/16 v5, 0xc

    invoke-direct {v10, v5}, Llyiahf/vczjk/tp3;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/ld9;

    new-instance v8, Llyiahf/vczjk/iy8;

    invoke-direct {v8}, Llyiahf/vczjk/iy8;-><init>()V

    iget-object v3, v3, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v3, Ljava/util/HashMap;

    invoke-static {v3}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v9

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/wc5;

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/wc5;Llyiahf/vczjk/pi4;Llyiahf/vczjk/iy8;Ljava/util/Map;Llyiahf/vczjk/tp3;)V

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ld9;->OooOooO(Llyiahf/vczjk/ed2;)V

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1a

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/o00O00o0;->OooO00o(Llyiahf/vczjk/ld9;)V

    goto :goto_d

    :cond_1a
    iget-object v0, v5, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/iy8;

    new-instance v3, Llyiahf/vczjk/gy8;

    iget-object v4, v0, Llyiahf/vczjk/iy8;->OooOOO0:Ljava/lang/StringBuilder;

    invoke-direct {v3, v4}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    iget-object v0, v0, Llyiahf/vczjk/iy8;->OooOOO:Ljava/util/ArrayDeque;

    invoke-virtual {v0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1b

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/fy8;

    iget-object v5, v4, Llyiahf/vczjk/fy8;->OooO00o:Ljava/lang/Object;

    iget v6, v4, Llyiahf/vczjk/fy8;->OooO0O0:I

    iget v7, v4, Llyiahf/vczjk/fy8;->OooO0OO:I

    iget v4, v4, Llyiahf/vczjk/fy8;->OooO0Oo:I

    invoke-virtual {v3, v5, v6, v7, v4}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    goto :goto_e

    :cond_1b
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_1c

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_1c

    new-instance v3, Landroid/text/SpannableStringBuilder;

    invoke-direct {v3, v1}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    :cond_1c
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_f
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1d

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v1, p1, v3}, Llyiahf/vczjk/o00O00o0;->OooO0Oo(Llyiahf/vczjk/dv1;Landroid/text/SpannableStringBuilder;)V

    goto :goto_f

    :cond_1d
    sget-object v0, Landroid/widget/TextView$BufferType;->SPANNABLE:Landroid/widget/TextView$BufferType;

    invoke-virtual {p1, v3, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;Landroid/widget/TextView$BufferType;)V

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_10
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1e

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o00O00o0;->OooO0O0(Llyiahf/vczjk/dv1;)V

    goto :goto_10

    :cond_1e
    iget-boolean v0, p0, Llyiahf/vczjk/pc5;->$disableLinkMovementMethod:Z

    if-eqz v0, :cond_1f

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setMovementMethod(Landroid/text/method/MovementMethod;)V

    :cond_1f
    iget-object v0, p0, Llyiahf/vczjk/pc5;->$onTextLayout:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_20

    new-instance v1, Llyiahf/vczjk/tm4;

    const/4 v2, 0x3

    invoke-direct {v1, v2, v0, p1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p1, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    :cond_20
    iget v0, p0, Llyiahf/vczjk/pc5;->$maxLines:I

    invoke-virtual {p1, v0}, Landroid/widget/TextView;->setMaxLines(I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_21
    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "input must not be null"

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

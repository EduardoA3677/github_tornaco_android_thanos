.class public final Llyiahf/vczjk/p11;
.super Llyiahf/vczjk/o00O00o0;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lg9;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/fv3;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/o11;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/o11;-><init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/fv3;)V

    iput-object v0, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yu2;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/jf0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/jf0;-><init>(Llyiahf/vczjk/yu2;)V

    iput-object v0, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO0O0(Llyiahf/vczjk/dv1;)V
    .locals 7

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    invoke-virtual {p1}, Landroidx/appcompat/widget/AppCompatTextView;->getText()Ljava/lang/CharSequence;

    move-result-object v0

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    instance-of v1, v0, Landroid/text/Spanned;

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Landroid/text/Spanned;

    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const-class v3, Llyiahf/vczjk/ve9;

    invoke-interface {v1, v2, v0, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    array-length v1, v0

    if-lez v1, :cond_2

    sget v1, Lio/noties/markwon/ext/tables/R$id;->markwon_tables_scheduler:I

    invoke-virtual {p1, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/qz;

    const/4 v3, 0x1

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/qz;-><init>(Llyiahf/vczjk/dv1;I)V

    invoke-virtual {p1, v1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    sget v3, Lio/noties/markwon/ext/tables/R$id;->markwon_tables_scheduler:I

    invoke-virtual {p1, v3, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_1
    new-instance v1, Llyiahf/vczjk/qx7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/qx7;-><init>(Llyiahf/vczjk/dv1;)V

    array-length p1, v0

    :goto_1
    if-ge v2, p1, :cond_2

    aget-object v3, v0, v2

    check-cast v3, Llyiahf/vczjk/ve9;

    iput-object v1, v3, Llyiahf/vczjk/ve9;->OooOo0o:Llyiahf/vczjk/qx7;

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_2
    return-void

    :pswitch_1
    sget v0, Lio/noties/markwon/R$id;->markwon_drawables_scheduler_last_text_hashcode:I

    invoke-virtual {p1, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    invoke-virtual {p1}, Landroidx/appcompat/widget/AppCompatTextView;->getText()Ljava/lang/CharSequence;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    if-eqz v0, :cond_3

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    if-ne v0, v1, :cond_3

    goto :goto_3

    :cond_3
    sget v0, Lio/noties/markwon/R$id;->markwon_drawables_scheduler_last_text_hashcode:I

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    invoke-static {p1}, Llyiahf/vczjk/mc4;->OooOoO0(Llyiahf/vczjk/dv1;)[Llyiahf/vczjk/sz;

    move-result-object v0

    if-eqz v0, :cond_5

    array-length v1, v0

    if-lez v1, :cond_5

    sget v1, Lio/noties/markwon/R$id;->markwon_drawables_scheduler:I

    invoke-virtual {p1, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_4

    new-instance v1, Llyiahf/vczjk/qz;

    const/4 v2, 0x0

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/qz;-><init>(Llyiahf/vczjk/dv1;I)V

    invoke-virtual {p1, v1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    sget v2, Lio/noties/markwon/R$id;->markwon_drawables_scheduler:I

    invoke-virtual {p1, v2, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_4
    new-instance v1, Llyiahf/vczjk/ra;

    const/4 v2, 0x1

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/ra;-><init>(Ljava/lang/Object;I)V

    array-length v2, v0

    const/4 v3, 0x0

    :goto_2
    if-ge v3, v2, :cond_5

    aget-object v4, v0, v3

    iget-object v4, v4, Llyiahf/vczjk/sz;->OooOOO:Llyiahf/vczjk/oz;

    new-instance v5, Llyiahf/vczjk/rz;

    invoke-virtual {v4}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    move-result-object v6

    invoke-direct {v5, p1, v1, v6}, Llyiahf/vczjk/rz;-><init>(Llyiahf/vczjk/dv1;Llyiahf/vczjk/ra;Landroid/graphics/Rect;)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/oz;->OooO0OO(Landroid/graphics/drawable/Drawable$Callback;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_2

    :cond_5
    :goto_3
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0OO()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jf0;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/jf0;->OooO0o0:Ljava/lang/Object;

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/jf0;->OooO0OO:Z

    iput v1, v0, Llyiahf/vczjk/jf0;->OooO0O0:I

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0Oo(Llyiahf/vczjk/dv1;Landroid/text/SpannableStringBuilder;)V
    .locals 3

    iget p2, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch p2, :pswitch_data_0

    return-void

    :pswitch_0
    invoke-virtual {p1}, Landroidx/appcompat/widget/AppCompatTextView;->getText()Ljava/lang/CharSequence;

    move-result-object p1

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p2

    const/4 v0, 0x0

    const/4 v1, 0x0

    if-nez p2, :cond_0

    instance-of p2, p1, Landroid/text/Spanned;

    if-eqz p2, :cond_0

    move-object p2, p1

    check-cast p2, Landroid/text/Spanned;

    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result p1

    const-class v2, Llyiahf/vczjk/ve9;

    invoke-interface {p2, v1, p1, v2}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-eqz p1, :cond_1

    array-length p2, p1

    if-lez p2, :cond_1

    array-length p2, p1

    :goto_1
    if-ge v1, p2, :cond_1

    aget-object v2, p1, v1

    check-cast v2, Llyiahf/vczjk/ve9;

    iput-object v0, v2, Llyiahf/vczjk/ve9;->OooOo0o:Llyiahf/vczjk/qx7;

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_1
    return-void

    :pswitch_1
    invoke-static {p1}, Llyiahf/vczjk/mc4;->OooooOO(Llyiahf/vczjk/dv1;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o(Llyiahf/vczjk/wc5;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/o11;

    iput-object v0, p1, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oO(Llyiahf/vczjk/ld9;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/og9;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/h69;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/h69;-><init>(I)V

    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ld9;->Oooo0oo(Ljava/lang/Iterable;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oo(Llyiahf/vczjk/tg7;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    return-void

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/qg9;

    iget-object v1, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/lg9;

    invoke-direct {v0, v1}, Llyiahf/vczjk/qg9;-><init>(Llyiahf/vczjk/lg9;)V

    const-class v1, Llyiahf/vczjk/mg9;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    return-void

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/qd0;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/qd0;-><init>(I)V

    const-class v1, Llyiahf/vczjk/ju3;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tg7;->Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public OooOO0(Llyiahf/vczjk/tqa;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/p11;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/xc9;

    const/16 v1, 0x13

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v1, Llyiahf/vczjk/mg9;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/p11;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jf0;

    new-instance v1, Llyiahf/vczjk/xc9;

    const/16 v2, 0x12

    invoke-direct {v1, v2}, Llyiahf/vczjk/xc9;-><init>(I)V

    const-class v2, Llyiahf/vczjk/he9;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v1, Llyiahf/vczjk/re9;

    const/4 v2, 0x3

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/re9;-><init>(Llyiahf/vczjk/jf0;I)V

    const-class v2, Llyiahf/vczjk/je9;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v1, Llyiahf/vczjk/re9;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/re9;-><init>(Llyiahf/vczjk/jf0;I)V

    const-class v2, Llyiahf/vczjk/se9;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v1, Llyiahf/vczjk/re9;

    const/4 v2, 0x1

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/re9;-><init>(Llyiahf/vczjk/jf0;I)V

    const-class v2, Llyiahf/vczjk/me9;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    new-instance v1, Llyiahf/vczjk/re9;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/re9;-><init>(Llyiahf/vczjk/jf0;I)V

    const-class v0, Llyiahf/vczjk/le9;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/tqa;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/cd5;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

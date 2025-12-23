.class public final Llyiahf/vczjk/ob;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/translation/ViewTranslationCallback;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/ob;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/ob;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ob;->OooO00o:Llyiahf/vczjk/ob;

    return-void
.end method


# virtual methods
.method public final onClearTranslation(Landroid/view/View;)Z
    .locals 13

    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getContentCaptureManager$ui_release()Llyiahf/vczjk/gc;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/cc;->OooOOO0:Llyiahf/vczjk/cc;

    iput-object v0, p1, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    invoke-virtual {p1}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object p1

    iget-object v0, p1, Llyiahf/vczjk/s14;->OooO0OO:[Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/s14;->OooO00o:[J

    array-length v1, p1

    add-int/lit8 v1, v1, -0x2

    if-ltz v1, :cond_5

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    aget-wide v4, p1, v3

    not-long v6, v4

    const/4 v8, 0x7

    shl-long/2addr v6, v8

    and-long/2addr v6, v4

    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v6, v8

    cmp-long v6, v6, v8

    if-eqz v6, :cond_4

    sub-int v6, v3, v1

    not-int v6, v6

    ushr-int/lit8 v6, v6, 0x1f

    const/16 v7, 0x8

    rsub-int/lit8 v6, v6, 0x8

    move v8, v2

    :goto_1
    if-ge v8, v6, :cond_3

    const-wide/16 v9, 0xff

    and-long/2addr v9, v4

    const-wide/16 v11, 0x80

    cmp-long v9, v9, v11

    if-gez v9, :cond_2

    shl-int/lit8 v9, v3, 0x3

    add-int/2addr v9, v8

    aget-object v9, v0, v9

    check-cast v9, Llyiahf/vczjk/te8;

    iget-object v9, v9, Llyiahf/vczjk/te8;->OooO00o:Llyiahf/vczjk/re8;

    iget-object v9, v9, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    sget-object v10, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    iget-object v9, v9, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    const/4 v11, 0x0

    if-nez v10, :cond_0

    move-object v10, v11

    :cond_0
    if-eqz v10, :cond_2

    sget-object v10, Llyiahf/vczjk/ie8;->OooOOO0:Llyiahf/vczjk/ze8;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_1

    goto :goto_2

    :cond_1
    move-object v11, v9

    :goto_2
    check-cast v11, Llyiahf/vczjk/o0O00O;

    if-eqz v11, :cond_2

    iget-object v9, v11, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v9, Llyiahf/vczjk/le3;

    if-eqz v9, :cond_2

    invoke-interface {v9}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    :cond_2
    shr-long/2addr v4, v7

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_3
    if-ne v6, v7, :cond_5

    :cond_4
    if-eq v3, v1, :cond_5

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_5
    const/4 p1, 0x1

    return p1
.end method

.method public final onHideTranslation(Landroid/view/View;)Z
    .locals 13

    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getContentCaptureManager$ui_release()Llyiahf/vczjk/gc;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/cc;->OooOOO0:Llyiahf/vczjk/cc;

    iput-object v0, p1, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    invoke-virtual {p1}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object p1

    iget-object v0, p1, Llyiahf/vczjk/s14;->OooO0OO:[Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/s14;->OooO00o:[J

    array-length v1, p1

    add-int/lit8 v1, v1, -0x2

    if-ltz v1, :cond_5

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    aget-wide v4, p1, v3

    not-long v6, v4

    const/4 v8, 0x7

    shl-long/2addr v6, v8

    and-long/2addr v6, v4

    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v6, v8

    cmp-long v6, v6, v8

    if-eqz v6, :cond_4

    sub-int v6, v3, v1

    not-int v6, v6

    ushr-int/lit8 v6, v6, 0x1f

    const/16 v7, 0x8

    rsub-int/lit8 v6, v6, 0x8

    move v8, v2

    :goto_1
    if-ge v8, v6, :cond_3

    const-wide/16 v9, 0xff

    and-long/2addr v9, v4

    const-wide/16 v11, 0x80

    cmp-long v9, v9, v11

    if-gez v9, :cond_2

    shl-int/lit8 v9, v3, 0x3

    add-int/2addr v9, v8

    aget-object v9, v0, v9

    check-cast v9, Llyiahf/vczjk/te8;

    iget-object v9, v9, Llyiahf/vczjk/te8;->OooO00o:Llyiahf/vczjk/re8;

    iget-object v9, v9, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    sget-object v10, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    iget-object v9, v9, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    const/4 v11, 0x0

    if-nez v10, :cond_0

    move-object v10, v11

    :cond_0
    sget-object v12, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v10, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    sget-object v10, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_1

    goto :goto_2

    :cond_1
    move-object v11, v9

    :goto_2
    check-cast v11, Llyiahf/vczjk/o0O00O;

    if-eqz v11, :cond_2

    iget-object v9, v11, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v9, Llyiahf/vczjk/oe3;

    if-eqz v9, :cond_2

    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v9, v10}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    :cond_2
    shr-long/2addr v4, v7

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_3
    if-ne v6, v7, :cond_5

    :cond_4
    if-eq v3, v1, :cond_5

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_5
    const/4 p1, 0x1

    return p1
.end method

.method public final onShowTranslation(Landroid/view/View;)Z
    .locals 13

    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.platform.AndroidComposeView"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getContentCaptureManager$ui_release()Llyiahf/vczjk/gc;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/cc;->OooOOO:Llyiahf/vczjk/cc;

    iput-object v0, p1, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    invoke-virtual {p1}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object p1

    iget-object v0, p1, Llyiahf/vczjk/s14;->OooO0OO:[Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/s14;->OooO00o:[J

    array-length v1, p1

    add-int/lit8 v1, v1, -0x2

    if-ltz v1, :cond_5

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    aget-wide v4, p1, v3

    not-long v6, v4

    const/4 v8, 0x7

    shl-long/2addr v6, v8

    and-long/2addr v6, v4

    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v6, v8

    cmp-long v6, v6, v8

    if-eqz v6, :cond_4

    sub-int v6, v3, v1

    not-int v6, v6

    ushr-int/lit8 v6, v6, 0x1f

    const/16 v7, 0x8

    rsub-int/lit8 v6, v6, 0x8

    move v8, v2

    :goto_1
    if-ge v8, v6, :cond_3

    const-wide/16 v9, 0xff

    and-long/2addr v9, v4

    const-wide/16 v11, 0x80

    cmp-long v9, v9, v11

    if-gez v9, :cond_2

    shl-int/lit8 v9, v3, 0x3

    add-int/2addr v9, v8

    aget-object v9, v0, v9

    check-cast v9, Llyiahf/vczjk/te8;

    iget-object v9, v9, Llyiahf/vczjk/te8;->OooO00o:Llyiahf/vczjk/re8;

    iget-object v9, v9, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    sget-object v10, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    iget-object v9, v9, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    const/4 v11, 0x0

    if-nez v10, :cond_0

    move-object v10, v11

    :cond_0
    sget-object v12, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v10, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    sget-object v10, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_1

    goto :goto_2

    :cond_1
    move-object v11, v9

    :goto_2
    check-cast v11, Llyiahf/vczjk/o0O00O;

    if-eqz v11, :cond_2

    iget-object v9, v11, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v9, Llyiahf/vczjk/oe3;

    if-eqz v9, :cond_2

    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v9, v10}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    :cond_2
    shr-long/2addr v4, v7

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_3
    if-ne v6, v7, :cond_5

    :cond_4
    if-eq v3, v1, :cond_5

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_5
    const/4 p1, 0x1

    return p1
.end method

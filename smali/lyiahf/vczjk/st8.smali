.class public final Llyiahf/vczjk/st8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $accessibilityManager:Llyiahf/vczjk/o0O0O0Oo;

.field final synthetic $currentSnackbarData:Llyiahf/vczjk/gt8;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gt8;Llyiahf/vczjk/o0O0O0Oo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/st8;->$currentSnackbarData:Llyiahf/vczjk/gt8;

    iput-object p2, p0, Llyiahf/vczjk/st8;->$accessibilityManager:Llyiahf/vczjk/o0O0O0Oo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/st8;

    iget-object v0, p0, Llyiahf/vczjk/st8;->$currentSnackbarData:Llyiahf/vczjk/gt8;

    iget-object v1, p0, Llyiahf/vczjk/st8;->$accessibilityManager:Llyiahf/vczjk/o0O0O0Oo;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/st8;-><init>(Llyiahf/vczjk/gt8;Llyiahf/vczjk/o0O0O0Oo;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/st8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/st8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/st8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/st8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_6

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/st8;->$currentSnackbarData:Llyiahf/vczjk/gt8;

    if-eqz p1, :cond_d

    check-cast p1, Llyiahf/vczjk/zt8;

    iget-object p1, p1, Llyiahf/vczjk/zt8;->OooO00o:Llyiahf/vczjk/au8;

    iget-object v1, p1, Llyiahf/vczjk/au8;->OooO0OO:Llyiahf/vczjk/it8;

    iget-object p1, p1, Llyiahf/vczjk/au8;->OooO0O0:Ljava/lang/String;

    if-eqz p1, :cond_2

    move p1, v2

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/st8;->$accessibilityManager:Llyiahf/vczjk/o0O0O0Oo;

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    const-wide v4, 0x7fffffffffffffffL

    if-eqz v1, :cond_5

    if-eq v1, v2, :cond_4

    const/4 v6, 0x2

    if-ne v1, v6, :cond_3

    move-wide v6, v4

    goto :goto_1

    :cond_3
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_4
    const-wide/16 v6, 0x2710

    goto :goto_1

    :cond_5
    const-wide/16 v6, 0xfa0

    :goto_1
    if-nez v3, :cond_6

    goto :goto_5

    :cond_6
    check-cast v3, Llyiahf/vczjk/l9;

    const-wide/32 v8, 0x7fffffff

    cmp-long v1, v6, v8

    if-ltz v1, :cond_7

    goto :goto_3

    :cond_7
    if-eqz p1, :cond_8

    const/4 v1, 0x7

    goto :goto_2

    :cond_8
    const/4 v1, 0x3

    :goto_2
    sget v8, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v9, 0x1d

    iget-object v3, v3, Llyiahf/vczjk/l9;->OooO00o:Landroid/view/accessibility/AccessibilityManager;

    if-lt v8, v9, :cond_a

    long-to-int p1, v6

    invoke-static {v3, p1, v1}, Llyiahf/vczjk/xo;->OooO0o0(Landroid/view/accessibility/AccessibilityManager;II)I

    move-result p1

    const v1, 0x7fffffff

    if-ne p1, v1, :cond_9

    goto :goto_4

    :cond_9
    int-to-long v4, p1

    goto :goto_4

    :cond_a
    if-eqz p1, :cond_b

    invoke-virtual {v3}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    move-result p1

    if-eqz p1, :cond_b

    goto :goto_4

    :cond_b
    :goto_3
    move-wide v4, v6

    :goto_4
    move-wide v6, v4

    :goto_5
    iput v2, p0, Llyiahf/vczjk/st8;->label:I

    invoke-static {v6, v7, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_c

    return-object v0

    :cond_c
    :goto_6
    iget-object p1, p0, Llyiahf/vczjk/st8;->$currentSnackbarData:Llyiahf/vczjk/gt8;

    check-cast p1, Llyiahf/vczjk/zt8;

    iget-object p1, p1, Llyiahf/vczjk/zt8;->OooO0O0:Llyiahf/vczjk/yp0;

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_d

    sget-object v0, Llyiahf/vczjk/ou8;->OooOOO0:Llyiahf/vczjk/ou8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_d
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final Llyiahf/vczjk/o00000O0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $offset:J

.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/o0000O0O;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o0000O0O;JLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o00000O0;->this$0:Llyiahf/vczjk/o0000O0O;

    iput-wide p2, p0, Llyiahf/vczjk/o00000O0;->$offset:J

    iput-object p4, p0, Llyiahf/vczjk/o00000O0;->$interactionSource:Llyiahf/vczjk/rr5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/o00000O0;

    iget-object v1, p0, Llyiahf/vczjk/o00000O0;->this$0:Llyiahf/vczjk/o0000O0O;

    iget-wide v2, p0, Llyiahf/vczjk/o00000O0;->$offset:J

    iget-object v4, p0, Llyiahf/vczjk/o00000O0;->$interactionSource:Llyiahf/vczjk/rr5;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o00000O0;-><init>(Llyiahf/vczjk/o0000O0O;JLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o00000O0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/o00000O0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o00000O0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/o00000O0;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/o00000O0;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/q37;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/o00000O0;->this$0:Llyiahf/vczjk/o0000O0O;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/dl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    sget-object v4, Llyiahf/vczjk/aa8;->OooOoo0:Llyiahf/vczjk/rp3;

    new-instance v5, Llyiahf/vczjk/tz0;

    invoke-direct {v5, v1}, Llyiahf/vczjk/tz0;-><init>(Llyiahf/vczjk/dl7;)V

    invoke-static {p1, v4, v5}, Llyiahf/vczjk/er8;->OooOo0O(Llyiahf/vczjk/l52;Ljava/lang/Object;Llyiahf/vczjk/oe3;)V

    iget-boolean v1, v1, Llyiahf/vczjk/dl7;->element:Z

    if-nez v1, :cond_4

    sget v1, Llyiahf/vczjk/yz0;->OooO0O0:I

    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    :goto_0
    if-eqz p1, :cond_5

    instance-of v1, p1, Landroid/view/ViewGroup;

    if-eqz v1, :cond_5

    check-cast p1, Landroid/view/ViewGroup;

    invoke-virtual {p1}, Landroid/view/ViewGroup;->shouldDelayChildPressedState()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_1

    :cond_3
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    goto :goto_0

    :cond_4
    :goto_1
    sget-wide v4, Llyiahf/vczjk/yz0;->OooO00o:J

    iput v3, p0, Llyiahf/vczjk/o00000O0;->label:I

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    goto :goto_3

    :cond_5
    :goto_2
    new-instance p1, Llyiahf/vczjk/q37;

    iget-wide v3, p0, Llyiahf/vczjk/o00000O0;->$offset:J

    invoke-direct {p1, v3, v4}, Llyiahf/vczjk/q37;-><init>(J)V

    iget-object v1, p0, Llyiahf/vczjk/o00000O0;->$interactionSource:Llyiahf/vczjk/rr5;

    iput-object p1, p0, Llyiahf/vczjk/o00000O0;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/o00000O0;->label:I

    check-cast v1, Llyiahf/vczjk/sr5;

    invoke-virtual {v1, p1, p0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_6

    :goto_3
    return-object v0

    :cond_6
    move-object v0, p1

    :goto_4
    iget-object p1, p0, Llyiahf/vczjk/o00000O0;->this$0:Llyiahf/vczjk/o0000O0O;

    iput-object v0, p1, Llyiahf/vczjk/o0000O0O;->Oooo0o0:Llyiahf/vczjk/q37;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final Llyiahf/vczjk/kq7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/jy4;

.field final synthetic $this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field L$4:Ljava/lang/Object;

.field L$5:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/xr1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/kq7;->$state:Llyiahf/vczjk/jy4;

    iput-object p3, p0, Llyiahf/vczjk/kq7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p4, p0, Llyiahf/vczjk/kq7;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/kq7;

    iget-object v1, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    iget-object v2, p0, Llyiahf/vczjk/kq7;->$state:Llyiahf/vczjk/jy4;

    iget-object v3, p0, Llyiahf/vczjk/kq7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iget-object v4, p0, Llyiahf/vczjk/kq7;->$block:Llyiahf/vczjk/ze3;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/kq7;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/xr1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/kq7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kq7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/kq7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/kq7;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$5:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ze3;

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$4:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xr1;

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$3:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ky4;

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jy4;

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$1:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/hl7;

    iget-object v0, p0, Llyiahf/vczjk/kq7;->L$0:Ljava/lang/Object;

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/hl7;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_3

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto/16 :goto_5

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-ne p1, v1, :cond_2

    goto/16 :goto_4

    :cond_2
    new-instance v7, Llyiahf/vczjk/hl7;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/kq7;->$state:Llyiahf/vczjk/jy4;

    iget-object v13, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    iget-object v8, p0, Llyiahf/vczjk/kq7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iget-object v12, p0, Llyiahf/vczjk/kq7;->$block:Llyiahf/vczjk/ze3;

    iput-object v7, p0, Llyiahf/vczjk/kq7;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/kq7;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/kq7;->L$2:Ljava/lang/Object;

    iput-object v13, p0, Llyiahf/vczjk/kq7;->L$3:Ljava/lang/Object;

    iput-object v8, p0, Llyiahf/vczjk/kq7;->L$4:Ljava/lang/Object;

    iput-object v12, p0, Llyiahf/vczjk/kq7;->L$5:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/kq7;->label:I

    new-instance v10, Llyiahf/vczjk/yp0;

    invoke-static {p0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v5

    invoke-direct {v10, v4, v5}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v10}, Llyiahf/vczjk/yp0;->OooOOoo()V

    sget-object v4, Llyiahf/vczjk/iy4;->Companion:Llyiahf/vczjk/gy4;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v4, "state"

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v4

    const/4 v5, 0x4

    const/4 v6, 0x3

    const/4 v9, 0x2

    if-eq v4, v9, :cond_5

    if-eq v4, v6, :cond_4

    if-eq v4, v5, :cond_3

    move-object v4, v3

    goto :goto_0

    :cond_3
    sget-object v4, Llyiahf/vczjk/iy4;->ON_RESUME:Llyiahf/vczjk/iy4;

    goto :goto_0

    :cond_4
    sget-object v4, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    goto :goto_0

    :cond_5
    sget-object v4, Llyiahf/vczjk/iy4;->ON_CREATE:Llyiahf/vczjk/iy4;

    :goto_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eq p1, v9, :cond_8

    if-eq p1, v6, :cond_7

    if-eq p1, v5, :cond_6

    move-object v9, v3

    goto :goto_2

    :cond_6
    sget-object p1, Llyiahf/vczjk/iy4;->ON_PAUSE:Llyiahf/vczjk/iy4;

    :goto_1
    move-object v9, p1

    goto :goto_2

    :cond_7
    sget-object p1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    goto :goto_1

    :cond_8
    sget-object p1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    goto :goto_1

    :goto_2
    new-instance v11, Llyiahf/vczjk/mt5;

    invoke-direct {v11}, Llyiahf/vczjk/mt5;-><init>()V

    new-instance v5, Llyiahf/vczjk/jq7;

    move-object v6, v4

    invoke-direct/range {v5 .. v12}, Llyiahf/vczjk/jq7;-><init>(Llyiahf/vczjk/iy4;Llyiahf/vczjk/hl7;Llyiahf/vczjk/xr1;Llyiahf/vczjk/iy4;Llyiahf/vczjk/yp0;Llyiahf/vczjk/mt5;Llyiahf/vczjk/ze3;)V

    iput-object v5, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    invoke-virtual {v10}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne p1, v0, :cond_9

    return-object v0

    :cond_9
    move-object v4, v7

    :goto_3
    iget-object p1, v4, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v74;

    if-eqz p1, :cond_a

    invoke-interface {p1, v3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_a
    iget-object p1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sy4;

    if-eqz p1, :cond_b

    iget-object v0, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    :cond_b
    :goto_4
    return-object v2

    :catchall_1
    move-exception v0

    move-object p1, v0

    move-object v4, v7

    :goto_5
    iget-object v0, v4, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    if-eqz v0, :cond_c

    invoke-interface {v0, v3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_c
    iget-object v0, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sy4;

    if-eqz v0, :cond_d

    iget-object v1, p0, Llyiahf/vczjk/kq7;->$this_repeatOnLifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    :cond_d
    throw p1
.end method

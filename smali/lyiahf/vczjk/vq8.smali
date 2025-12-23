.class public final Llyiahf/vczjk/vq8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $targetSize:J

.field final synthetic $this_apply:Llyiahf/vczjk/uq8;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/xq8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uq8;JLlyiahf/vczjk/xq8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vq8;->$this_apply:Llyiahf/vczjk/uq8;

    iput-wide p2, p0, Llyiahf/vczjk/vq8;->$targetSize:J

    iput-object p4, p0, Llyiahf/vczjk/vq8;->this$0:Llyiahf/vczjk/xq8;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/vq8;

    iget-object v1, p0, Llyiahf/vczjk/vq8;->$this_apply:Llyiahf/vczjk/uq8;

    iget-wide v2, p0, Llyiahf/vczjk/vq8;->$targetSize:J

    iget-object v4, p0, Llyiahf/vczjk/vq8;->this$0:Llyiahf/vczjk/xq8;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/vq8;-><init>(Llyiahf/vczjk/uq8;JLlyiahf/vczjk/xq8;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vq8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vq8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vq8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vq8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v7, p0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/vq8;->$this_apply:Llyiahf/vczjk/uq8;

    iget-object v3, p1, Llyiahf/vczjk/uq8;->OooO00o:Llyiahf/vczjk/gi;

    iget-wide v4, p0, Llyiahf/vczjk/vq8;->$targetSize:J

    move-wide v5, v4

    new-instance v4, Llyiahf/vczjk/b24;

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/b24;-><init>(J)V

    iget-object p1, p0, Llyiahf/vczjk/vq8;->this$0:Llyiahf/vczjk/xq8;

    iget-object v5, p1, Llyiahf/vczjk/xq8;->OooOoOO:Llyiahf/vczjk/wz8;

    iput v2, p0, Llyiahf/vczjk/vq8;->label:I

    const/4 v6, 0x0

    const/16 v8, 0xc

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    check-cast p1, Llyiahf/vczjk/el;

    iget-object p1, p1, Llyiahf/vczjk/el;->OooO0O0:Llyiahf/vczjk/zk;

    sget-object v0, Llyiahf/vczjk/zk;->OooOOO:Llyiahf/vczjk/zk;

    if-ne p1, v0, :cond_3

    iget-object p1, v7, Llyiahf/vczjk/vq8;->this$0:Llyiahf/vczjk/xq8;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

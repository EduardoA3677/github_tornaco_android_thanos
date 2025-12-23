.class public final Llyiahf/vczjk/lf9;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $onPress:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $onTap:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $pressScope:Llyiahf/vczjk/o37;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/lf9;->$onPress:Llyiahf/vczjk/bf3;

    iput-object p3, p0, Llyiahf/vczjk/lf9;->$onTap:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {p0, p5}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/lf9;

    iget-object v1, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iget-object v2, p0, Llyiahf/vczjk/lf9;->$onPress:Llyiahf/vczjk/bf3;

    iget-object v3, p0, Llyiahf/vczjk/lf9;->$onTap:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/lf9;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lf9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lf9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lf9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/lf9;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    const/4 v4, 0x2

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v4, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/lf9;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v3, p0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    iget-object v1, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    sget-object v5, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    sget-object v5, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v6, Llyiahf/vczjk/kf9;

    iget-object v7, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v6, v7, v2}, Llyiahf/vczjk/kf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v2, v5, v6, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v1

    iput-object p1, p0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/lf9;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/lf9;->label:I

    const/4 v3, 0x3

    invoke-static {p1, p0, v3}, Llyiahf/vczjk/dg9;->OooO0OO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/rs7;I)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object v9, v3

    move-object v3, p1

    move-object p1, v9

    :goto_0
    check-cast p1, Llyiahf/vczjk/ky6;

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v5, p0, Llyiahf/vczjk/lf9;->$onPress:Llyiahf/vczjk/bf3;

    sget-object v6, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    if-eq v5, v6, :cond_4

    iget-object v6, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v7, Llyiahf/vczjk/hf9;

    iget-object v8, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v7, v5, v8, p1, v2}, Llyiahf/vczjk/hf9;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/o37;Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V

    invoke-static {v6, v1, v7}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    :cond_4
    iput-object v1, p0, Llyiahf/vczjk/lf9;->L$0:Ljava/lang/Object;

    iput-object v2, p0, Llyiahf/vczjk/lf9;->L$1:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/lf9;->label:I

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v3, p1, p0}, Llyiahf/vczjk/dg9;->OooO0oO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_1
    return-object v0

    :cond_5
    move-object v0, v1

    :goto_2
    check-cast p1, Llyiahf/vczjk/ky6;

    if-nez p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/if9;

    iget-object v3, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/if9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    goto :goto_3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v1, p0, Llyiahf/vczjk/lf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v3, Llyiahf/vczjk/jf9;

    iget-object v4, p0, Llyiahf/vczjk/lf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/jf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v0, v3}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    iget-object v0, p0, Llyiahf/vczjk/lf9;->$onTap:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_7

    new-instance v1, Llyiahf/vczjk/p86;

    iget-wide v2, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_7
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

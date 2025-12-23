.class public final Llyiahf/vczjk/da8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $offset:J

.field final synthetic $previousValue:Llyiahf/vczjk/el7;

.field final synthetic $this_semanticsScrollBy:Llyiahf/vczjk/db8;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/db8;JLlyiahf/vczjk/el7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/da8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    iput-wide p2, p0, Llyiahf/vczjk/da8;->$offset:J

    iput-object p4, p0, Llyiahf/vczjk/da8;->$previousValue:Llyiahf/vczjk/el7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/da8;

    iget-object v1, p0, Llyiahf/vczjk/da8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    iget-wide v2, p0, Llyiahf/vczjk/da8;->$offset:J

    iget-object v4, p0, Llyiahf/vczjk/da8;->$previousValue:Llyiahf/vczjk/el7;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/da8;-><init>(Llyiahf/vczjk/db8;JLlyiahf/vczjk/el7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/da8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/lz5;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/da8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/da8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/da8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/da8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/da8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/lz5;

    iget-object v1, p0, Llyiahf/vczjk/da8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    iget-wide v3, p0, Llyiahf/vczjk/da8;->$offset:J

    invoke-virtual {v1, v3, v4}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result v6

    new-instance v8, Llyiahf/vczjk/ca8;

    iget-object v1, p0, Llyiahf/vczjk/da8;->$previousValue:Llyiahf/vczjk/el7;

    iget-object v3, p0, Llyiahf/vczjk/da8;->$this_semanticsScrollBy:Llyiahf/vczjk/db8;

    invoke-direct {v8, v1, v3, p1}, Llyiahf/vczjk/ca8;-><init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/db8;Llyiahf/vczjk/lz5;)V

    iput v2, p0, Llyiahf/vczjk/da8;->label:I

    const/4 v7, 0x0

    const/16 v10, 0xc

    const/4 v5, 0x0

    move-object v9, p0

    invoke-static/range {v5 .. v10}, Llyiahf/vczjk/vc6;->OooOO0(FFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

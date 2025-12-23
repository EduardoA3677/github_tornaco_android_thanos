.class public final Llyiahf/vczjk/ak;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $shape:Llyiahf/vczjk/ir1;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/fk;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ak;->this$0:Llyiahf/vczjk/fk;

    iput-object p2, p0, Llyiahf/vczjk/ak;->$shape:Llyiahf/vczjk/ir1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/ak;

    iget-object v0, p0, Llyiahf/vczjk/ak;->this$0:Llyiahf/vczjk/fk;

    iget-object v1, p0, Llyiahf/vczjk/ak;->$shape:Llyiahf/vczjk/ir1;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/ak;-><init>(Llyiahf/vczjk/fk;Llyiahf/vczjk/ir1;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ak;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ak;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ak;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ak;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/ak;->this$0:Llyiahf/vczjk/fk;

    iget-object v3, p1, Llyiahf/vczjk/fk;->OooO0o0:Llyiahf/vczjk/gi;

    if-eqz v3, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/ak;->$shape:Llyiahf/vczjk/ir1;

    iget-object v1, v1, Llyiahf/vczjk/ir1;->OooOOO0:Llyiahf/vczjk/lr1;

    iget-wide v4, p1, Llyiahf/vczjk/fk;->OooO0OO:J

    iget-object p1, p1, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    invoke-interface {v1, v4, v5, p1}, Llyiahf/vczjk/lr1;->OooO00o(JLlyiahf/vczjk/f62;)F

    move-result p1

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    iget-object p1, p0, Llyiahf/vczjk/ak;->this$0:Llyiahf/vczjk/fk;

    iget-object v5, p1, Llyiahf/vczjk/fk;->OooO0O0:Llyiahf/vczjk/p13;

    iput v2, p0, Llyiahf/vczjk/ak;->label:I

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

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

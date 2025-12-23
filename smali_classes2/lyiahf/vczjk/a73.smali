.class public final Llyiahf/vczjk/a73;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $transform$inlined:Llyiahf/vczjk/gf3;

.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/a73;->$transform$inlined:Llyiahf/vczjk/gf3;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, [Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/a73;

    iget-object v1, p0, Llyiahf/vczjk/a73;->$transform$inlined:Llyiahf/vczjk/gf3;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/a73;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V

    iput-object p1, v0, Llyiahf/vczjk/a73;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/a73;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a73;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/a73;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/a73;->L$0:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/h43;

    iget-object p1, p0, Llyiahf/vczjk/a73;->L$1:Ljava/lang/Object;

    check-cast p1, [Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/a73;->$transform$inlined:Llyiahf/vczjk/gf3;

    const/4 v1, 0x0

    aget-object v5, p1, v1

    aget-object v6, p1, v2

    const/4 v1, 0x2

    aget-object v7, p1, v1

    const/4 v1, 0x3

    aget-object v8, p1, v1

    const/4 v1, 0x4

    aget-object v9, p1, v1

    iput v2, p0, Llyiahf/vczjk/a73;->label:I

    move-object v10, p0

    invoke-interface/range {v3 .. v10}, Llyiahf/vczjk/gf3;->OooO0Oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/io/Serializable;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

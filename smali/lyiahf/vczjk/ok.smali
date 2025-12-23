.class public final Llyiahf/vczjk/ok;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $childTransition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $shouldDisposeBlockUpdated$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ok;->$childTransition:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/ok;->$shouldDisposeBlockUpdated$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ok;

    iget-object v1, p0, Llyiahf/vczjk/ok;->$childTransition:Llyiahf/vczjk/bz9;

    iget-object v2, p0, Llyiahf/vczjk/ok;->$shouldDisposeBlockUpdated$delegate:Llyiahf/vczjk/p29;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ok;-><init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ok;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/p77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ok;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ok;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ok;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ok;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/ok;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/p77;

    new-instance v1, Llyiahf/vczjk/mk;

    iget-object v3, p0, Llyiahf/vczjk/ok;->$childTransition:Llyiahf/vczjk/bz9;

    invoke-direct {v1, v3}, Llyiahf/vczjk/mk;-><init>(Llyiahf/vczjk/bz9;)V

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/nk;

    iget-object v4, p0, Llyiahf/vczjk/ok;->$childTransition:Llyiahf/vczjk/bz9;

    iget-object v5, p0, Llyiahf/vczjk/ok;->$shouldDisposeBlockUpdated$delegate:Llyiahf/vczjk/p29;

    const/4 v6, 0x0

    invoke-direct {v3, p1, v4, v6, v5}, Llyiahf/vczjk/nk;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iput v2, p0, Llyiahf/vczjk/ok;->label:I

    invoke-virtual {v1, v3, p0}, Llyiahf/vczjk/o00O0000;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final Llyiahf/vczjk/ia8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $forEachDelta:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $this_with:Llyiahf/vczjk/db8;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/db8;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/ia8;->$forEachDelta:Llyiahf/vczjk/ze3;

    iput-object p3, p0, Llyiahf/vczjk/ia8;->$this_with:Llyiahf/vczjk/db8;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ia8;

    iget-object v1, p0, Llyiahf/vczjk/ia8;->$forEachDelta:Llyiahf/vczjk/ze3;

    iget-object v2, p0, Llyiahf/vczjk/ia8;->$this_with:Llyiahf/vczjk/db8;

    invoke-direct {v0, p2, v1, v2}, Llyiahf/vczjk/ia8;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/db8;)V

    iput-object p1, v0, Llyiahf/vczjk/ia8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/lz5;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ia8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ia8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ia8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ia8;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/ia8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/lz5;

    iget-object v1, p0, Llyiahf/vczjk/ia8;->$forEachDelta:Llyiahf/vczjk/ze3;

    new-instance v3, Llyiahf/vczjk/ha8;

    iget-object v4, p0, Llyiahf/vczjk/ia8;->$this_with:Llyiahf/vczjk/db8;

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/ha8;-><init>(Llyiahf/vczjk/lz5;Llyiahf/vczjk/db8;)V

    iput v2, p0, Llyiahf/vczjk/ia8;->label:I

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

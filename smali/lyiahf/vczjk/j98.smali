.class public final Llyiahf/vczjk/j98;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $consumed:Llyiahf/vczjk/el7;

.field final synthetic $value:F

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/j98;->$consumed:Llyiahf/vczjk/el7;

    iput p2, p0, Llyiahf/vczjk/j98;->$value:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/j98;

    iget-object v1, p0, Llyiahf/vczjk/j98;->$consumed:Llyiahf/vczjk/el7;

    iget v2, p0, Llyiahf/vczjk/j98;->$value:F

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/j98;-><init>(Llyiahf/vczjk/el7;FLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/j98;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j98;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j98;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j98;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/j98;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/j98;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v98;

    iget-object v0, p0, Llyiahf/vczjk/j98;->$consumed:Llyiahf/vczjk/el7;

    iget v1, p0, Llyiahf/vczjk/j98;->$value:F

    invoke-interface {p1, v1}, Llyiahf/vczjk/v98;->OooO00o(F)F

    move-result p1

    iput p1, v0, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

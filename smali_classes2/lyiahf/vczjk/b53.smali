.class public final Llyiahf/vczjk/b53;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $downstream:Llyiahf/vczjk/h43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h43;"
        }
    .end annotation
.end field

.field final synthetic $lastValue:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/b53;->$downstream:Llyiahf/vczjk/h43;

    iput-object p3, p0, Llyiahf/vczjk/b53;->$lastValue:Llyiahf/vczjk/hl7;

    const/4 p2, 0x1

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/b53;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b53;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/b53;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/b53;

    iget-object v1, p0, Llyiahf/vczjk/b53;->$downstream:Llyiahf/vczjk/h43;

    iget-object v2, p0, Llyiahf/vczjk/b53;->$lastValue:Llyiahf/vczjk/hl7;

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/b53;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/b53;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/b53;->$downstream:Llyiahf/vczjk/h43;

    sget-object v1, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    iget-object v4, p0, Llyiahf/vczjk/b53;->$lastValue:Llyiahf/vczjk/hl7;

    iget-object v4, v4, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-ne v4, v1, :cond_2

    move-object v4, v2

    :cond_2
    iput v3, p0, Llyiahf/vczjk/b53;->label:I

    invoke-interface {p1, v4, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/b53;->$lastValue:Llyiahf/vczjk/hl7;

    iput-object v2, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

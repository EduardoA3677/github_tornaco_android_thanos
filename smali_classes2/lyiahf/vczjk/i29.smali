.class public final Llyiahf/vczjk/i29;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/h43;

.field public final synthetic OooOOO0:Llyiahf/vczjk/dl7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/h43;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i29;->OooOOO0:Llyiahf/vczjk/dl7;

    iput-object p2, p0, Llyiahf/vczjk/i29;->OooOOO:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final OooO00o(ILlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/h29;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/h29;

    iget v1, v0, Llyiahf/vczjk/h29;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/h29;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/h29;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/h29;-><init>(Llyiahf/vczjk/i29;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/h29;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/h29;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v4, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    if-lez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/i29;->OooOOO0:Llyiahf/vczjk/dl7;

    iget-boolean p2, p1, Llyiahf/vczjk/dl7;->element:Z

    if-nez p2, :cond_3

    iput-boolean v4, p1, Llyiahf/vczjk/dl7;->element:Z

    sget-object p1, Llyiahf/vczjk/pl8;->OooOOO0:Llyiahf/vczjk/pl8;

    iput v4, v0, Llyiahf/vczjk/h29;->label:I

    iget-object p2, p0, Llyiahf/vczjk/i29;->OooOOO:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    return-object v3
.end method

.method public final bridge synthetic emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/i29;->OooO00o(ILlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

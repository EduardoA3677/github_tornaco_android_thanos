.class public final Llyiahf/vczjk/bu6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $onClearInputHandled:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $pinInput$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $shouldClearInput:Z

.field label:I


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/bu6;->$shouldClearInput:Z

    iput-object p2, p0, Llyiahf/vczjk/bu6;->$onClearInputHandled:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/bu6;->$pinInput$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/bu6;

    iget-boolean v0, p0, Llyiahf/vczjk/bu6;->$shouldClearInput:Z

    iget-object v1, p0, Llyiahf/vczjk/bu6;->$onClearInputHandled:Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/bu6;->$pinInput$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/bu6;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bu6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bu6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/bu6;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean p1, p0, Llyiahf/vczjk/bu6;->$shouldClearInput:Z

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/bu6;->$pinInput$delegate:Llyiahf/vczjk/qs5;

    const-string v0, ""

    invoke-interface {p1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/bu6;->$onClearInputHandled:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

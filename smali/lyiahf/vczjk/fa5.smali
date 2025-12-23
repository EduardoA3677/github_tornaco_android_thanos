.class public final Llyiahf/vczjk/fa5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $shizukuState$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $waitDialogState:Llyiahf/vczjk/p97;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/p97;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fa5;->$waitDialogState:Llyiahf/vczjk/p97;

    iput-object p2, p0, Llyiahf/vczjk/fa5;->$shizukuState$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/fa5;

    iget-object v0, p0, Llyiahf/vczjk/fa5;->$waitDialogState:Llyiahf/vczjk/p97;

    iget-object v1, p0, Llyiahf/vczjk/fa5;->$shizukuState$delegate:Llyiahf/vczjk/p29;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/fa5;-><init>(Llyiahf/vczjk/p97;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fa5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fa5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fa5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/fa5;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fa5;->$shizukuState$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rm8;

    iget-boolean p1, p1, Llyiahf/vczjk/rm8;->OooO00o:Z

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/fa5;->$shizukuState$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rm8;

    iget-boolean p1, p1, Llyiahf/vczjk/rm8;->OooO0O0:Z

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/fa5;->$waitDialogState:Llyiahf/vczjk/p97;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/fa5;->$waitDialogState:Llyiahf/vczjk/p97;

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

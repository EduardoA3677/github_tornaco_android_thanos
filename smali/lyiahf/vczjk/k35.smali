.class public final Llyiahf/vczjk/k35;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

.field final synthetic $globalRotation:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $morphProgress:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

.field final synthetic $morphSequence:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ao5;",
            ">;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Ljava/util/List;Llyiahf/vczjk/qr5;Llyiahf/vczjk/lr5;Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k35;->$morphProgress:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/k35;->$morphSequence:Ljava/util/List;

    iput-object p3, p0, Llyiahf/vczjk/k35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    iput-object p4, p0, Llyiahf/vczjk/k35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    iput-object p5, p0, Llyiahf/vczjk/k35;->$globalRotation:Llyiahf/vczjk/gi;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/k35;

    iget-object v1, p0, Llyiahf/vczjk/k35;->$morphProgress:Llyiahf/vczjk/gi;

    iget-object v2, p0, Llyiahf/vczjk/k35;->$morphSequence:Ljava/util/List;

    iget-object v3, p0, Llyiahf/vczjk/k35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    iget-object v4, p0, Llyiahf/vczjk/k35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    iget-object v5, p0, Llyiahf/vczjk/k35;->$globalRotation:Llyiahf/vczjk/gi;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/k35;-><init>(Llyiahf/vczjk/gi;Ljava/util/List;Llyiahf/vczjk/qr5;Llyiahf/vczjk/lr5;Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/k35;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/k35;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/k35;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/k35;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/k35;->label:I

    if-eqz v0, :cond_1

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/k35;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Llyiahf/vczjk/k35;->$morphProgress:Llyiahf/vczjk/gi;

    iget-object v2, p0, Llyiahf/vczjk/k35;->$morphSequence:Ljava/util/List;

    iget-object v3, p0, Llyiahf/vczjk/k35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    iget-object v4, p0, Llyiahf/vczjk/k35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    iget-object v6, p0, Llyiahf/vczjk/k35;->$globalRotation:Llyiahf/vczjk/gi;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v0

    sget-object v5, Llyiahf/vczjk/pp3;->OooOOo0:Llyiahf/vczjk/pp3;

    invoke-interface {v0, v5}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v0

    if-nez v0, :cond_2

    new-instance v0, Llyiahf/vczjk/i35;

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/i35;-><init>(Llyiahf/vczjk/gi;Ljava/util/List;Llyiahf/vczjk/qr5;Llyiahf/vczjk/lr5;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x0

    const/4 v2, 0x3

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/j35;

    invoke-direct {v0, v6, v1}, Llyiahf/vczjk/j35;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

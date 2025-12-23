.class public final Llyiahf/vczjk/h35;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

.field final synthetic $morphAnimationSpec:Llyiahf/vczjk/wz8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wz8;"
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

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/wz8;Ljava/util/List;Llyiahf/vczjk/qr5;Llyiahf/vczjk/lr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h35;->$morphProgress:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/h35;->$morphAnimationSpec:Llyiahf/vczjk/wz8;

    iput-object p3, p0, Llyiahf/vczjk/h35;->$morphSequence:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/h35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    iput-object p5, p0, Llyiahf/vczjk/h35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/h35;

    iget-object v1, p0, Llyiahf/vczjk/h35;->$morphProgress:Llyiahf/vczjk/gi;

    iget-object v2, p0, Llyiahf/vczjk/h35;->$morphAnimationSpec:Llyiahf/vczjk/wz8;

    iget-object v3, p0, Llyiahf/vczjk/h35;->$morphSequence:Ljava/util/List;

    iget-object v4, p0, Llyiahf/vczjk/h35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    iget-object v5, p0, Llyiahf/vczjk/h35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/h35;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/wz8;Ljava/util/List;Llyiahf/vczjk/qr5;Llyiahf/vczjk/lr5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/h35;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/h35;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h35;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/h35;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v8, p0

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v8, p0

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v4, p0, Llyiahf/vczjk/h35;->$morphProgress:Llyiahf/vczjk/gi;

    new-instance v5, Ljava/lang/Float;

    const/high16 p1, 0x3f800000    # 1.0f

    invoke-direct {v5, p1}, Ljava/lang/Float;-><init>(F)V

    iget-object v6, p0, Llyiahf/vczjk/h35;->$morphAnimationSpec:Llyiahf/vczjk/wz8;

    iput v3, p0, Llyiahf/vczjk/h35;->label:I

    const/4 v7, 0x0

    const/16 v9, 0xc

    move-object v8, p0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    check-cast p1, Llyiahf/vczjk/el;

    iget-object p1, p1, Llyiahf/vczjk/el;->OooO0O0:Llyiahf/vczjk/zk;

    sget-object v1, Llyiahf/vczjk/zk;->OooOOO:Llyiahf/vczjk/zk;

    if-ne p1, v1, :cond_5

    iget-object p1, v8, Llyiahf/vczjk/h35;->$currentMorphIndex$delegate:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    add-int/2addr v1, v3

    iget-object v3, v8, Llyiahf/vczjk/h35;->$morphSequence:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    rem-int/2addr v1, v3

    invoke-virtual {p1, v1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-object p1, v8, Llyiahf/vczjk/h35;->$morphProgress:Llyiahf/vczjk/gi;

    new-instance v1, Ljava/lang/Float;

    const/4 v3, 0x0

    invoke-direct {v1, v3}, Ljava/lang/Float;-><init>(F)V

    iput v2, v8, Llyiahf/vczjk/h35;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    iget-object p1, v8, Llyiahf/vczjk/h35;->$morphRotationTargetAngle$delegate:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    const/high16 v1, 0x42b40000    # 90.0f

    add-float/2addr v0, v1

    const/high16 v1, 0x43b40000    # 360.0f

    rem-float/2addr v0, v1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

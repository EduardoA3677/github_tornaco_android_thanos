.class public final Llyiahf/vczjk/h98;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationSpec:Llyiahf/vczjk/wl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wl;"
        }
    .end annotation
.end field

.field final synthetic $previousValue:Llyiahf/vczjk/el7;

.field final synthetic $value:F

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/wl;Llyiahf/vczjk/el7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/h98;->$value:F

    iput-object p2, p0, Llyiahf/vczjk/h98;->$animationSpec:Llyiahf/vczjk/wl;

    iput-object p3, p0, Llyiahf/vczjk/h98;->$previousValue:Llyiahf/vczjk/el7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/h98;

    iget v1, p0, Llyiahf/vczjk/h98;->$value:F

    iget-object v2, p0, Llyiahf/vczjk/h98;->$animationSpec:Llyiahf/vczjk/wl;

    iget-object v3, p0, Llyiahf/vczjk/h98;->$previousValue:Llyiahf/vczjk/el7;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/h98;-><init>(FLlyiahf/vczjk/wl;Llyiahf/vczjk/el7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/h98;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/h98;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/h98;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h98;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/h98;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/h98;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v98;

    iget v4, p0, Llyiahf/vczjk/h98;->$value:F

    iget-object v5, p0, Llyiahf/vczjk/h98;->$animationSpec:Llyiahf/vczjk/wl;

    new-instance v6, Llyiahf/vczjk/g98;

    iget-object v1, p0, Llyiahf/vczjk/h98;->$previousValue:Llyiahf/vczjk/el7;

    invoke-direct {v6, v1, p1}, Llyiahf/vczjk/g98;-><init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/v98;)V

    iput v2, p0, Llyiahf/vczjk/h98;->label:I

    const/4 v3, 0x0

    const/4 v8, 0x4

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/vc6;->OooOO0(FFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

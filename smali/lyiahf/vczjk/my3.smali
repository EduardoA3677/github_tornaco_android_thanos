.class public final Llyiahf/vczjk/my3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $animationSpec:Llyiahf/vczjk/cy3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/cy3;"
        }
    .end annotation
.end field

.field final synthetic $initialValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $targetValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $transitionAnimation:Llyiahf/vczjk/dy3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/dy3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Number;Llyiahf/vczjk/dy3;Ljava/lang/Number;Llyiahf/vczjk/cy3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/my3;->$initialValue:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/my3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    iput-object p3, p0, Llyiahf/vczjk/my3;->$targetValue:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/my3;->$animationSpec:Llyiahf/vczjk/cy3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/my3;->$initialValue:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/my3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    iget-object v1, v1, Llyiahf/vczjk/dy3;->OooOOO0:Ljava/lang/Object;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/my3;->$targetValue:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/my3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    iget-object v1, v1, Llyiahf/vczjk/dy3;->OooOOO:Ljava/lang/Object;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/my3;->$transitionAnimation:Llyiahf/vczjk/dy3;

    iget-object v4, p0, Llyiahf/vczjk/my3;->$initialValue:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/my3;->$targetValue:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/my3;->$animationSpec:Llyiahf/vczjk/cy3;

    iput-object v4, v0, Llyiahf/vczjk/dy3;->OooOOO0:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/dy3;->OooOOO:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/dy3;->OooOOo0:Llyiahf/vczjk/wl;

    new-instance v1, Llyiahf/vczjk/fg9;

    iget-object v3, v0, Llyiahf/vczjk/dy3;->OooOOOO:Llyiahf/vczjk/n1a;

    const/4 v6, 0x0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    iput-object v1, v0, Llyiahf/vczjk/dy3;->OooOOo:Llyiahf/vczjk/fg9;

    iget-object v1, v0, Llyiahf/vczjk/dy3;->OooOo0O:Llyiahf/vczjk/jy3;

    iget-object v1, v1, Llyiahf/vczjk/jy3;->OooO0O0:Llyiahf/vczjk/qs5;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/dy3;->OooOOoo:Z

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/dy3;->OooOo00:Z

    :cond_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

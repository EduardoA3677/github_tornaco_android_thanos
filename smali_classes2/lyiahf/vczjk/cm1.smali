.class public final Llyiahf/vczjk/cm1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $lifecycleState:Llyiahf/vczjk/jy4;

.field final synthetic $sideEffect:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $this_collectSideEffect:Llyiahf/vczjk/zl1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zl1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zl1;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cm1;->$this_collectSideEffect:Llyiahf/vczjk/zl1;

    iput-object p2, p0, Llyiahf/vczjk/cm1;->$lifecycleState:Llyiahf/vczjk/jy4;

    iput-object p3, p0, Llyiahf/vczjk/cm1;->$sideEffect:Llyiahf/vczjk/ze3;

    iput p4, p0, Llyiahf/vczjk/cm1;->$$changed:I

    iput p5, p0, Llyiahf/vczjk/cm1;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/cm1;->$this_collectSideEffect:Llyiahf/vczjk/zl1;

    iget-object v1, p0, Llyiahf/vczjk/cm1;->$lifecycleState:Llyiahf/vczjk/jy4;

    iget-object v2, p0, Llyiahf/vczjk/cm1;->$sideEffect:Llyiahf/vczjk/ze3;

    iget p1, p0, Llyiahf/vczjk/cm1;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v4

    iget v5, p0, Llyiahf/vczjk/cm1;->$$default:I

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/so8;->OooOo0O(Llyiahf/vczjk/zl1;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

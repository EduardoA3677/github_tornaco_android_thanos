.class public final Llyiahf/vczjk/gz9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $animationSpec:Llyiahf/vczjk/p13;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p13;"
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

.field final synthetic $this_UpdateInitialAndTargetValues:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $transitionAnimation:Llyiahf/vczjk/uy9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/uy9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/uy9;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/p13;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gz9;->$this_UpdateInitialAndTargetValues:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/gz9;->$transitionAnimation:Llyiahf/vczjk/uy9;

    iput-object p3, p0, Llyiahf/vczjk/gz9;->$initialValue:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/gz9;->$targetValue:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/gz9;->$animationSpec:Llyiahf/vczjk/p13;

    iput p6, p0, Llyiahf/vczjk/gz9;->$$changed:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/gz9;->$this_UpdateInitialAndTargetValues:Llyiahf/vczjk/bz9;

    iget-object v1, p0, Llyiahf/vczjk/gz9;->$transitionAnimation:Llyiahf/vczjk/uy9;

    iget-object v2, p0, Llyiahf/vczjk/gz9;->$initialValue:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/gz9;->$targetValue:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/gz9;->$animationSpec:Llyiahf/vczjk/p13;

    iget p1, p0, Llyiahf/vczjk/gz9;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/oz9;->OooO00o(Llyiahf/vczjk/bz9;Llyiahf/vczjk/uy9;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/p13;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

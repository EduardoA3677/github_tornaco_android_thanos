.class public final Llyiahf/vczjk/t72;
.super Llyiahf/vczjk/fc5;
.source "SourceFile"


# static fields
.field public static final OooOOOO:I

.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _deserFeatures:I

.field protected final _formatReadFeatures:I

.field protected final _formatReadFeaturesToChange:I

.field protected final _nodeFactory:Llyiahf/vczjk/ua4;

.field protected final _parserFeatures:I

.field protected final _parserFeaturesToChange:I

.field protected final _problemHandlers:Llyiahf/vczjk/j05;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/j05;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-class v0, Llyiahf/vczjk/w72;

    invoke-static {v0}, Llyiahf/vczjk/ec5;->OooO0OO(Ljava/lang/Class;)I

    move-result v0

    sput v0, Llyiahf/vczjk/t72;->OooOOOO:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/t72;IIIIII)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/fc5;-><init>(Llyiahf/vczjk/fc5;I)V

    iput p3, p0, Llyiahf/vczjk/t72;->_deserFeatures:I

    iget-object p2, p1, Llyiahf/vczjk/t72;->_nodeFactory:Llyiahf/vczjk/ua4;

    iput-object p2, p0, Llyiahf/vczjk/t72;->_nodeFactory:Llyiahf/vczjk/ua4;

    iget-object p1, p1, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    iput-object p1, p0, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    iput p4, p0, Llyiahf/vczjk/t72;->_parserFeatures:I

    iput p5, p0, Llyiahf/vczjk/t72;->_parserFeaturesToChange:I

    iput p6, p0, Llyiahf/vczjk/t72;->_formatReadFeatures:I

    iput p7, p0, Llyiahf/vczjk/t72;->_formatReadFeaturesToChange:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V
    .locals 0

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/fc5;-><init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V

    move-object p1, p0

    sget p2, Llyiahf/vczjk/t72;->OooOOOO:I

    iput p2, p1, Llyiahf/vczjk/t72;->_deserFeatures:I

    sget-object p2, Llyiahf/vczjk/ua4;->OooOOO0:Llyiahf/vczjk/ua4;

    iput-object p2, p1, Llyiahf/vczjk/t72;->_nodeFactory:Llyiahf/vczjk/ua4;

    const/4 p2, 0x0

    iput-object p2, p1, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    const/4 p2, 0x0

    iput p2, p1, Llyiahf/vczjk/t72;->_parserFeatures:I

    iput p2, p1, Llyiahf/vczjk/t72;->_parserFeaturesToChange:I

    iput p2, p1, Llyiahf/vczjk/t72;->_formatReadFeatures:I

    iput p2, p1, Llyiahf/vczjk/t72;->_formatReadFeaturesToChange:I

    return-void
.end method


# virtual methods
.method public final OooOo00(I)Llyiahf/vczjk/fc5;
    .locals 8

    new-instance v0, Llyiahf/vczjk/t72;

    iget v3, p0, Llyiahf/vczjk/t72;->_deserFeatures:I

    iget v4, p0, Llyiahf/vczjk/t72;->_parserFeatures:I

    iget v5, p0, Llyiahf/vczjk/t72;->_parserFeaturesToChange:I

    iget v6, p0, Llyiahf/vczjk/t72;->_formatReadFeatures:I

    iget v7, p0, Llyiahf/vczjk/t72;->_formatReadFeaturesToChange:I

    move-object v1, p0

    move v2, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/t72;-><init>(Llyiahf/vczjk/t72;IIIIII)V

    return-object v0
.end method

.method public final Oooo0(Llyiahf/vczjk/w72;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t72;->_deserFeatures:I

    invoke-virtual {p1}, Llyiahf/vczjk/w72;->OooO0O0()I

    move-result p1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final Oooo00O(Llyiahf/vczjk/eb4;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/t72;->_parserFeaturesToChange:I

    if-eqz v0, :cond_0

    iget v1, p0, Llyiahf/vczjk/t72;->_parserFeatures:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/eb4;->o0000ooO(II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/t72;->_formatReadFeaturesToChange:I

    if-eqz v0, :cond_1

    iget v1, p0, Llyiahf/vczjk/t72;->_formatReadFeatures:I

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/eb4;->o0000oo0(II)V

    :cond_1
    return-void
.end method

.method public final Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;
    .locals 7

    invoke-virtual {p0}, Llyiahf/vczjk/ec5;->OooO0oO()Llyiahf/vczjk/jy0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/l90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0, p1}, Llyiahf/vczjk/l90;->OooO0O0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/l90;->OooO00o(Llyiahf/vczjk/fc5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-static {p0, p1, p0}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v5

    new-instance v1, Llyiahf/vczjk/yg6;

    const-string v6, "set"

    const/4 v3, 0x0

    move-object v2, p0

    move-object v4, p1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/yg6;-><init>(Llyiahf/vczjk/fc5;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/hm;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h90;

    invoke-direct {p1, v1}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/yg6;)V

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final Oooo0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fc5;->_rootName:Llyiahf/vczjk/xa7;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    return v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/w72;->OooOooo:Llyiahf/vczjk/w72;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/t72;->Oooo0(Llyiahf/vczjk/w72;)Z

    move-result v0

    return v0
.end method

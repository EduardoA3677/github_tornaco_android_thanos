.class public final Llyiahf/vczjk/pm6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $initialPage:I

.field final synthetic $initialPageOffsetFraction:F

.field final synthetic $pageCount:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/pm6;->$initialPage:I

    const/4 v1, 0x0

    iput v1, p0, Llyiahf/vczjk/pm6;->$initialPageOffsetFraction:F

    iput-object p1, p0, Llyiahf/vczjk/pm6;->$pageCount:Llyiahf/vczjk/le3;

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/d32;

    iget v1, p0, Llyiahf/vczjk/pm6;->$initialPage:I

    iget v2, p0, Llyiahf/vczjk/pm6;->$initialPageOffsetFraction:F

    iget-object v3, p0, Llyiahf/vczjk/pm6;->$pageCount:Llyiahf/vczjk/le3;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/d32;-><init>(IFLlyiahf/vczjk/le3;)V

    return-object v0
.end method

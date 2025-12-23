.class public final Llyiahf/vczjk/gr4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $initialFirstVisibleItemIndex:I

.field final synthetic $initialFirstVisibleItemScrollOffset:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/gr4;->$initialFirstVisibleItemIndex:I

    iput v0, p0, Llyiahf/vczjk/gr4;->$initialFirstVisibleItemScrollOffset:I

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/er4;

    iget v1, p0, Llyiahf/vczjk/gr4;->$initialFirstVisibleItemIndex:I

    iget v2, p0, Llyiahf/vczjk/gr4;->$initialFirstVisibleItemScrollOffset:I

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/er4;-><init>(II)V

    return-object v0
.end method

.class public final Llyiahf/vczjk/od8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $currentRawOffset:I

.field final synthetic $info:Llyiahf/vczjk/id8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/id8;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/od8;->$info:Llyiahf/vczjk/id8;

    iput p2, p0, Llyiahf/vczjk/od8;->$currentRawOffset:I

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/od8;->$info:Llyiahf/vczjk/id8;

    iget-object v0, v0, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    iget v1, p0, Llyiahf/vczjk/od8;->$currentRawOffset:I

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0
.end method

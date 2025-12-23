.class public final Llyiahf/vczjk/dw3;
.super Llyiahf/vczjk/fw3;
.source "SourceFile"


# instance fields
.field public final transient OooOOOO:I

.field public final transient OooOOOo:I

.field final synthetic this$0:Llyiahf/vczjk/fw3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fw3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    iput p2, p0, Llyiahf/vczjk/dw3;->OooOOOO:I

    iput p3, p0, Llyiahf/vczjk/dw3;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final OooO0O0()[Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    invoke-virtual {v0}, Llyiahf/vczjk/yv3;->OooO0O0()[Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    invoke-virtual {v0}, Llyiahf/vczjk/yv3;->OooO0o()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/dw3;->OooOOOO:I

    add-int/2addr v0, v1

    iget v1, p0, Llyiahf/vczjk/dw3;->OooOOOo:I

    add-int/2addr v0, v1

    return v0
.end method

.method public final OooO0o()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    invoke-virtual {v0}, Llyiahf/vczjk/yv3;->OooO0o()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/dw3;->OooOOOO:I

    add-int/2addr v0, v1

    return v0
.end method

.method public final OooOO0O(II)Llyiahf/vczjk/fw3;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/dw3;->OooOOOo:I

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/tp6;->OooOOOO(III)V

    iget-object v0, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    iget v1, p0, Llyiahf/vczjk/dw3;->OooOOOO:I

    add-int/2addr p1, v1

    add-int/2addr p2, v1

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/fw3;->OooOO0O(II)Llyiahf/vczjk/fw3;

    move-result-object p1

    return-object p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/dw3;->OooOOOo:I

    invoke-static {p1, v0}, Llyiahf/vczjk/tp6;->OooOOO0(II)V

    iget-object v0, p0, Llyiahf/vczjk/dw3;->this$0:Llyiahf/vczjk/fw3;

    iget v1, p0, Llyiahf/vczjk/dw3;->OooOOOO:I

    add-int/2addr p1, v1

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fw3;->OooO(I)Llyiahf/vczjk/aw3;

    move-result-object v0

    return-object v0
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fw3;->OooO(I)Llyiahf/vczjk/aw3;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic listIterator(I)Ljava/util/ListIterator;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/fw3;->OooO(I)Llyiahf/vczjk/aw3;

    move-result-object p1

    return-object p1
.end method

.method public final size()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/dw3;->OooOOOo:I

    return v0
.end method

.method public final bridge synthetic subList(II)Ljava/util/List;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/dw3;->OooOO0O(II)Llyiahf/vczjk/fw3;

    move-result-object p1

    return-object p1
.end method

.method public writeReplace()Ljava/lang/Object;
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/fw3;->writeReplace()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

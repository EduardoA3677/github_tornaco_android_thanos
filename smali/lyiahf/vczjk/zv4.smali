.class public final Llyiahf/vczjk/zv4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $firstVisibleItemIndex:I

.field final synthetic this$0:Llyiahf/vczjk/dw4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dw4;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zv4;->this$0:Llyiahf/vczjk/dw4;

    iput p2, p0, Llyiahf/vczjk/zv4;->$firstVisibleItemIndex:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/iu4;

    iget-object v0, p0, Llyiahf/vczjk/zv4;->this$0:Llyiahf/vczjk/dw4;

    iget-object v0, v0, Llyiahf/vczjk/dw4;->OooO00o:Llyiahf/vczjk/o0OoOo0;

    iget v1, p0, Llyiahf/vczjk/zv4;->$firstVisibleItemIndex:I

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v3

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    invoke-static {v2}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v2, v4, v3}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    const/4 v2, 0x0

    :goto_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v3, 0x2

    if-ge v2, v3, :cond_1

    add-int v3, v1, v2

    invoke-virtual {p1, v3}, Llyiahf/vczjk/iu4;->OooO00o(I)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final Llyiahf/vczjk/bb5;
.super Llyiahf/vczjk/db5;
.source "SourceFile"

# interfaces
.implements Ljava/util/Iterator;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public final synthetic OooOOo0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bb5;->OooOOo0:I

    const-string p2, "map"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/db5;->OooOOOo:Ljava/lang/Object;

    const/4 p2, -0x1

    iput p2, p0, Llyiahf/vczjk/db5;->OooOOO:I

    invoke-static {p1}, Llyiahf/vczjk/eb5;->OooO0Oo(Llyiahf/vczjk/eb5;)I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/db5;->OooOOOO:I

    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0oo()V

    return-void
.end method


# virtual methods
.method public final next()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/bb5;->OooOOo0:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0O0()V

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iget-object v1, p0, Llyiahf/vczjk/db5;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eb5;

    invoke-static {v1}, Llyiahf/vczjk/eb5;->OooO0O0(Llyiahf/vczjk/eb5;)I

    move-result v2

    if-ge v0, v2, :cond_0

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    add-int/lit8 v2, v0, 0x1

    iput v2, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iput v0, p0, Llyiahf/vczjk/db5;->OooOOO:I

    invoke-static {v1}, Llyiahf/vczjk/eb5;->OooO0oo(Llyiahf/vczjk/eb5;)[Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v1, p0, Llyiahf/vczjk/db5;->OooOOO:I

    aget-object v0, v0, v1

    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0oo()V

    return-object v0

    :cond_0
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0O0()V

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iget-object v1, p0, Llyiahf/vczjk/db5;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eb5;

    invoke-static {v1}, Llyiahf/vczjk/eb5;->OooO0O0(Llyiahf/vczjk/eb5;)I

    move-result v2

    if-ge v0, v2, :cond_1

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    add-int/lit8 v2, v0, 0x1

    iput v2, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iput v0, p0, Llyiahf/vczjk/db5;->OooOOO:I

    invoke-static {v1}, Llyiahf/vczjk/eb5;->OooO00o(Llyiahf/vczjk/eb5;)[Ljava/lang/Object;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/db5;->OooOOO:I

    aget-object v0, v0, v1

    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0oo()V

    return-object v0

    :cond_1
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0

    :pswitch_1
    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0O0()V

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iget-object v1, p0, Llyiahf/vczjk/db5;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eb5;

    invoke-static {v1}, Llyiahf/vczjk/eb5;->OooO0O0(Llyiahf/vczjk/eb5;)I

    move-result v2

    if-ge v0, v2, :cond_2

    iget v0, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    add-int/lit8 v2, v0, 0x1

    iput v2, p0, Llyiahf/vczjk/db5;->OooOOO0:I

    iput v0, p0, Llyiahf/vczjk/db5;->OooOOO:I

    new-instance v2, Llyiahf/vczjk/cb5;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/cb5;-><init>(Llyiahf/vczjk/eb5;I)V

    invoke-virtual {p0}, Llyiahf/vczjk/db5;->OooO0oo()V

    return-object v2

    :cond_2
    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    throw v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

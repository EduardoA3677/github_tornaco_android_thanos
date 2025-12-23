.class public final synthetic Llyiahf/vczjk/hu8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;ILlyiahf/vczjk/ow6;IILlyiahf/vczjk/ow6;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hu8;->OooOOO0:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/hu8;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/hu8;->OooOOOO:Llyiahf/vczjk/ow6;

    iput p4, p0, Llyiahf/vczjk/hu8;->OooOOOo:I

    iput p5, p0, Llyiahf/vczjk/hu8;->OooOOo0:I

    iput-object p6, p0, Llyiahf/vczjk/hu8;->OooOOo:Llyiahf/vczjk/ow6;

    iput p7, p0, Llyiahf/vczjk/hu8;->OooOOoo:I

    iput p8, p0, Llyiahf/vczjk/hu8;->OooOo00:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/hu8;->OooOOO0:Llyiahf/vczjk/ow6;

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/hu8;->OooOOO:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v0, p0, Llyiahf/vczjk/hu8;->OooOOOO:Llyiahf/vczjk/ow6;

    if-eqz v0, :cond_0

    iget v1, p0, Llyiahf/vczjk/hu8;->OooOOOo:I

    iget v2, p0, Llyiahf/vczjk/hu8;->OooOOo0:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/hu8;->OooOOo:Llyiahf/vczjk/ow6;

    if-eqz v0, :cond_1

    iget v1, p0, Llyiahf/vczjk/hu8;->OooOOoo:I

    iget v2, p0, Llyiahf/vczjk/hu8;->OooOo00:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

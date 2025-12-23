.class public final synthetic Llyiahf/vczjk/fx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;IILlyiahf/vczjk/ow6;IIII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fx5;->OooOOO0:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/fx5;->OooOOO:Llyiahf/vczjk/ow6;

    iput p3, p0, Llyiahf/vczjk/fx5;->OooOOOO:I

    iput p4, p0, Llyiahf/vczjk/fx5;->OooOOOo:I

    iput-object p5, p0, Llyiahf/vczjk/fx5;->OooOOo0:Llyiahf/vczjk/ow6;

    iput p6, p0, Llyiahf/vczjk/fx5;->OooOOo:I

    iput p7, p0, Llyiahf/vczjk/fx5;->OooOOoo:I

    iput p8, p0, Llyiahf/vczjk/fx5;->OooOo00:I

    iput p9, p0, Llyiahf/vczjk/fx5;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/fx5;->OooOOO0:Llyiahf/vczjk/ow6;

    if-eqz v0, :cond_0

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p0, Llyiahf/vczjk/fx5;->OooOo00:I

    sub-int/2addr v2, v1

    div-int/lit8 v2, v2, 0x2

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v3, p0, Llyiahf/vczjk/fx5;->OooOo0:I

    sub-int/2addr v3, v1

    div-int/lit8 v3, v3, 0x2

    invoke-static {p1, v0, v2, v3}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fx5;->OooOOO:Llyiahf/vczjk/ow6;

    iget v1, p0, Llyiahf/vczjk/fx5;->OooOOOO:I

    iget v2, p0, Llyiahf/vczjk/fx5;->OooOOOo:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v0, p0, Llyiahf/vczjk/fx5;->OooOOo0:Llyiahf/vczjk/ow6;

    iget v1, p0, Llyiahf/vczjk/fx5;->OooOOo:I

    iget v2, p0, Llyiahf/vczjk/fx5;->OooOOoo:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

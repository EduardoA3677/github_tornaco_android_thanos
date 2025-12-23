.class public final synthetic Llyiahf/vczjk/uf6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/xf6;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/n24;

.field public final synthetic OooOOo:Llyiahf/vczjk/ei9;

.field public final synthetic OooOOo0:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOoo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOo0:F

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:I

.field public final synthetic OooOo0o:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xf6;ZZLlyiahf/vczjk/n24;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;FFII)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/uf6;->OooOOO0:Llyiahf/vczjk/xf6;

    iput-boolean p2, p0, Llyiahf/vczjk/uf6;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/uf6;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/uf6;->OooOOOo:Llyiahf/vczjk/n24;

    iput-object p5, p0, Llyiahf/vczjk/uf6;->OooOOo0:Llyiahf/vczjk/hl5;

    iput-object p6, p0, Llyiahf/vczjk/uf6;->OooOOo:Llyiahf/vczjk/ei9;

    iput-object p7, p0, Llyiahf/vczjk/uf6;->OooOOoo:Llyiahf/vczjk/qj8;

    iput p8, p0, Llyiahf/vczjk/uf6;->OooOo00:F

    iput p9, p0, Llyiahf/vczjk/uf6;->OooOo0:F

    iput p10, p0, Llyiahf/vczjk/uf6;->OooOo0O:I

    iput p11, p0, Llyiahf/vczjk/uf6;->OooOo0o:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/uf6;->OooOo0O:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget-object v5, p0, Llyiahf/vczjk/uf6;->OooOOo:Llyiahf/vczjk/ei9;

    iget v8, p0, Llyiahf/vczjk/uf6;->OooOo0:F

    iget v11, p0, Llyiahf/vczjk/uf6;->OooOo0o:I

    iget-object v0, p0, Llyiahf/vczjk/uf6;->OooOOO0:Llyiahf/vczjk/xf6;

    iget-boolean v1, p0, Llyiahf/vczjk/uf6;->OooOOO:Z

    iget-boolean v2, p0, Llyiahf/vczjk/uf6;->OooOOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/uf6;->OooOOOo:Llyiahf/vczjk/n24;

    iget-object v4, p0, Llyiahf/vczjk/uf6;->OooOOo0:Llyiahf/vczjk/hl5;

    iget-object v6, p0, Llyiahf/vczjk/uf6;->OooOOoo:Llyiahf/vczjk/qj8;

    iget v7, p0, Llyiahf/vczjk/uf6;->OooOo00:F

    invoke-virtual/range {v0 .. v11}, Llyiahf/vczjk/xf6;->OooO00o(ZZLlyiahf/vczjk/n24;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;FFLlyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

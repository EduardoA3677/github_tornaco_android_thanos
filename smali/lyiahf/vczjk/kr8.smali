.class public final synthetic Llyiahf/vczjk/kr8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cs8;

.field public final synthetic OooOOO0:Llyiahf/vczjk/pr8;

.field public final synthetic OooOOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/ir8;

.field public final synthetic OooOOoo:Llyiahf/vczjk/bf3;

.field public final synthetic OooOo0:F

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/pr8;Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;FFI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kr8;->OooOOO0:Llyiahf/vczjk/pr8;

    iput-object p2, p0, Llyiahf/vczjk/kr8;->OooOOO:Llyiahf/vczjk/cs8;

    iput-object p3, p0, Llyiahf/vczjk/kr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iput-boolean p4, p0, Llyiahf/vczjk/kr8;->OooOOOo:Z

    iput-object p5, p0, Llyiahf/vczjk/kr8;->OooOOo0:Llyiahf/vczjk/ir8;

    iput-object p6, p0, Llyiahf/vczjk/kr8;->OooOOo:Llyiahf/vczjk/ze3;

    iput-object p7, p0, Llyiahf/vczjk/kr8;->OooOOoo:Llyiahf/vczjk/bf3;

    iput p8, p0, Llyiahf/vczjk/kr8;->OooOo00:F

    iput p9, p0, Llyiahf/vczjk/kr8;->OooOo0:F

    iput p10, p0, Llyiahf/vczjk/kr8;->OooOo0O:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/kr8;->OooOo0O:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget v7, p0, Llyiahf/vczjk/kr8;->OooOo00:F

    iget v8, p0, Llyiahf/vczjk/kr8;->OooOo0:F

    iget-object v0, p0, Llyiahf/vczjk/kr8;->OooOOO0:Llyiahf/vczjk/pr8;

    iget-object v1, p0, Llyiahf/vczjk/kr8;->OooOOO:Llyiahf/vczjk/cs8;

    iget-object v2, p0, Llyiahf/vczjk/kr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iget-boolean v3, p0, Llyiahf/vczjk/kr8;->OooOOOo:Z

    iget-object v4, p0, Llyiahf/vczjk/kr8;->OooOOo0:Llyiahf/vczjk/ir8;

    iget-object v5, p0, Llyiahf/vczjk/kr8;->OooOOo:Llyiahf/vczjk/ze3;

    iget-object v6, p0, Llyiahf/vczjk/kr8;->OooOOoo:Llyiahf/vczjk/bf3;

    invoke-virtual/range {v0 .. v10}, Llyiahf/vczjk/pr8;->OooO0O0(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;FFLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

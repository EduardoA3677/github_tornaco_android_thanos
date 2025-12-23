.class public final synthetic Llyiahf/vczjk/lf0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/nf0;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:Llyiahf/vczjk/ir1;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nf0;Llyiahf/vczjk/hl5;FFLlyiahf/vczjk/ir1;JI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lf0;->OooOOO0:Llyiahf/vczjk/nf0;

    iput-object p2, p0, Llyiahf/vczjk/lf0;->OooOOO:Llyiahf/vczjk/hl5;

    iput p3, p0, Llyiahf/vczjk/lf0;->OooOOOO:F

    iput p4, p0, Llyiahf/vczjk/lf0;->OooOOOo:F

    iput-object p5, p0, Llyiahf/vczjk/lf0;->OooOOo0:Llyiahf/vczjk/ir1;

    iput-wide p6, p0, Llyiahf/vczjk/lf0;->OooOOo:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const p1, 0x30001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object v4, p0, Llyiahf/vczjk/lf0;->OooOOo0:Llyiahf/vczjk/ir1;

    iget-wide v5, p0, Llyiahf/vczjk/lf0;->OooOOo:J

    iget-object v0, p0, Llyiahf/vczjk/lf0;->OooOOO0:Llyiahf/vczjk/nf0;

    iget-object v1, p0, Llyiahf/vczjk/lf0;->OooOOO:Llyiahf/vczjk/hl5;

    iget v2, p0, Llyiahf/vczjk/lf0;->OooOOOO:F

    iget v3, p0, Llyiahf/vczjk/lf0;->OooOOOo:F

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/nf0;->OooO00o(Llyiahf/vczjk/hl5;FFLlyiahf/vczjk/ir1;JLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

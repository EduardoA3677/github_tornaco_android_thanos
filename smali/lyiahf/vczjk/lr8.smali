.class public final synthetic Llyiahf/vczjk/lr8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/rr5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/pr8;

.field public final synthetic OooOOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ir8;

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:Z


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/pr8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ir8;ZJI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lr8;->OooOOO0:Llyiahf/vczjk/pr8;

    iput-object p2, p0, Llyiahf/vczjk/lr8;->OooOOO:Llyiahf/vczjk/rr5;

    iput-object p3, p0, Llyiahf/vczjk/lr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iput-object p4, p0, Llyiahf/vczjk/lr8;->OooOOOo:Llyiahf/vczjk/ir8;

    iput-boolean p5, p0, Llyiahf/vczjk/lr8;->OooOOo0:Z

    iput-wide p6, p0, Llyiahf/vczjk/lr8;->OooOOo:J

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

    iget-boolean v4, p0, Llyiahf/vczjk/lr8;->OooOOo0:Z

    iget-wide v5, p0, Llyiahf/vczjk/lr8;->OooOOo:J

    iget-object v0, p0, Llyiahf/vczjk/lr8;->OooOOO0:Llyiahf/vczjk/pr8;

    iget-object v1, p0, Llyiahf/vczjk/lr8;->OooOOO:Llyiahf/vczjk/rr5;

    iget-object v2, p0, Llyiahf/vczjk/lr8;->OooOOOO:Llyiahf/vczjk/hl5;

    iget-object v3, p0, Llyiahf/vczjk/lr8;->OooOOOo:Llyiahf/vczjk/ir8;

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/pr8;->OooO00o(Llyiahf/vczjk/rr5;Llyiahf/vczjk/hl5;Llyiahf/vczjk/ir8;ZJLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

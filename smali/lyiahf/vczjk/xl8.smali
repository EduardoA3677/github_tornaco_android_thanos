.class public final synthetic Llyiahf/vczjk/xl8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:Z


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/xl8;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/xl8;->OooOOO:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/xl8;->OooOOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/xl8;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-boolean p5, p0, Llyiahf/vczjk/xl8;->OooOOo0:Z

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/am8;

    new-instance v0, Llyiahf/vczjk/zl8;

    iget-object v5, p0, Llyiahf/vczjk/xl8;->OooOOOo:Llyiahf/vczjk/oe3;

    iget-boolean v6, p0, Llyiahf/vczjk/xl8;->OooOOo0:Z

    iget-boolean v1, p0, Llyiahf/vczjk/xl8;->OooOOO0:Z

    iget-object v2, p0, Llyiahf/vczjk/xl8;->OooOOO:Llyiahf/vczjk/le3;

    iget-object v3, p0, Llyiahf/vczjk/xl8;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/zl8;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/am8;Llyiahf/vczjk/oe3;Z)V

    return-object v0
.end method

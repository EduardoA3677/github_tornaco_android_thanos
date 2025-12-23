.class public final synthetic Llyiahf/vczjk/lx8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/util/List;

.field public final synthetic OooOOO0:Llyiahf/vczjk/vw;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/vw;Ljava/util/List;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lx8;->OooOOO0:Llyiahf/vczjk/vw;

    iput-object p2, p0, Llyiahf/vczjk/lx8;->OooOOO:Ljava/util/List;

    iput-boolean p3, p0, Llyiahf/vczjk/lx8;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/lx8;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/lx8;->OooOOo0:Llyiahf/vczjk/oe3;

    iput-boolean p6, p0, Llyiahf/vczjk/lx8;->OooOOo:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v4, p0, Llyiahf/vczjk/lx8;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-boolean v5, p0, Llyiahf/vczjk/lx8;->OooOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/lx8;->OooOOO0:Llyiahf/vczjk/vw;

    iget-object v1, p0, Llyiahf/vczjk/lx8;->OooOOO:Ljava/util/List;

    iget-boolean v2, p0, Llyiahf/vczjk/lx8;->OooOOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/lx8;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/vt6;->OooOOO(Llyiahf/vczjk/vw;Ljava/util/List;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

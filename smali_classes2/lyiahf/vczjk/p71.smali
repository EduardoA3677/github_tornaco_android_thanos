.class public final synthetic Llyiahf/vczjk/p71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/b71;

.field public final synthetic OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOoo:Z

.field public final synthetic OooOo00:Llyiahf/vczjk/ze3;


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;ZZLlyiahf/vczjk/ze3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p71;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iput-object p2, p0, Llyiahf/vczjk/p71;->OooOOO:Llyiahf/vczjk/b71;

    iput-boolean p3, p0, Llyiahf/vczjk/p71;->OooOOOO:Z

    iput-boolean p4, p0, Llyiahf/vczjk/p71;->OooOOOo:Z

    iput-object p5, p0, Llyiahf/vczjk/p71;->OooOOo0:Llyiahf/vczjk/oe3;

    iput-boolean p6, p0, Llyiahf/vczjk/p71;->OooOOo:Z

    iput-boolean p7, p0, Llyiahf/vczjk/p71;->OooOOoo:Z

    iput-object p8, p0, Llyiahf/vczjk/p71;->OooOo00:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p1, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    const p1, 0x1000001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v1, p0, Llyiahf/vczjk/p71;->OooOOO:Llyiahf/vczjk/b71;

    iget-boolean v6, p0, Llyiahf/vczjk/p71;->OooOOoo:Z

    iget-object v7, p0, Llyiahf/vczjk/p71;->OooOo00:Llyiahf/vczjk/ze3;

    iget-object v0, p0, Llyiahf/vczjk/p71;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iget-boolean v2, p0, Llyiahf/vczjk/p71;->OooOOOO:Z

    iget-boolean v3, p0, Llyiahf/vczjk/p71;->OooOOOo:Z

    iget-object v4, p0, Llyiahf/vczjk/p71;->OooOOo0:Llyiahf/vczjk/oe3;

    iget-boolean v5, p0, Llyiahf/vczjk/p71;->OooOOo:Z

    invoke-virtual/range {v0 .. v9}, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OooOooO(Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

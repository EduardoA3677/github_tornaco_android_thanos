.class public final synthetic Llyiahf/vczjk/n71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/e71;

.field public final synthetic OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

.field public final synthetic OooOOOO:Llyiahf/vczjk/r71;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/e71;Llyiahf/vczjk/r71;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n71;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iput-object p2, p0, Llyiahf/vczjk/n71;->OooOOO:Llyiahf/vczjk/e71;

    iput-object p3, p0, Llyiahf/vczjk/n71;->OooOOOO:Llyiahf/vczjk/r71;

    iput-boolean p4, p0, Llyiahf/vczjk/n71;->OooOOOo:Z

    iput-boolean p5, p0, Llyiahf/vczjk/n71;->OooOOo0:Z

    iput-object p6, p0, Llyiahf/vczjk/n71;->OooOOo:Llyiahf/vczjk/ze3;

    iput-object p7, p0, Llyiahf/vczjk/n71;->OooOOoo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p1, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    const p1, 0x200031

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v8

    iget-object v5, p0, Llyiahf/vczjk/n71;->OooOOo:Llyiahf/vczjk/ze3;

    iget-object v6, p0, Llyiahf/vczjk/n71;->OooOOoo:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/n71;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iget-object v1, p0, Llyiahf/vczjk/n71;->OooOOO:Llyiahf/vczjk/e71;

    iget-object v2, p0, Llyiahf/vczjk/n71;->OooOOOO:Llyiahf/vczjk/r71;

    iget-boolean v3, p0, Llyiahf/vczjk/n71;->OooOOOo:Z

    iget-boolean v4, p0, Llyiahf/vczjk/n71;->OooOOo0:Z

    invoke-virtual/range {v0 .. v8}, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OooOoo(Llyiahf/vczjk/e71;Llyiahf/vczjk/r71;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

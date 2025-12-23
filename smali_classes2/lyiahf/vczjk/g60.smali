.class public final synthetic Llyiahf/vczjk/g60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Llyiahf/vczjk/le3;

.field public final synthetic OooOo:I

.field public final synthetic OooOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOo00:Ljava/util/List;

.field public final synthetic OooOo0O:Llyiahf/vczjk/a91;

.field public final synthetic OooOo0o:Llyiahf/vczjk/a91;

.field public final synthetic OooOoO:I

.field public final synthetic OooOoO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Ljava/util/List;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;III)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g60;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-boolean p2, p0, Llyiahf/vczjk/g60;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/g60;->OooOOOO:Z

    iput-boolean p4, p0, Llyiahf/vczjk/g60;->OooOOOo:Z

    iput-boolean p5, p0, Llyiahf/vczjk/g60;->OooOOo0:Z

    iput-object p6, p0, Llyiahf/vczjk/g60;->OooOOo:Llyiahf/vczjk/le3;

    iput-object p7, p0, Llyiahf/vczjk/g60;->OooOOoo:Llyiahf/vczjk/le3;

    iput-object p8, p0, Llyiahf/vczjk/g60;->OooOo00:Ljava/util/List;

    iput-object p9, p0, Llyiahf/vczjk/g60;->OooOo0:Llyiahf/vczjk/a91;

    iput-object p10, p0, Llyiahf/vczjk/g60;->OooOo0O:Llyiahf/vczjk/a91;

    iput-object p11, p0, Llyiahf/vczjk/g60;->OooOo0o:Llyiahf/vczjk/a91;

    iput p12, p0, Llyiahf/vczjk/g60;->OooOo:I

    iput p13, p0, Llyiahf/vczjk/g60;->OooOoO0:I

    iput p14, p0, Llyiahf/vczjk/g60;->OooOoO:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v0, Llyiahf/vczjk/g60;->OooOo:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v13

    iget v1, v0, Llyiahf/vczjk/g60;->OooOoO0:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v14

    iget-object v11, v0, Llyiahf/vczjk/g60;->OooOo0o:Llyiahf/vczjk/a91;

    iget v15, v0, Llyiahf/vczjk/g60;->OooOoO:I

    iget-object v1, v0, Llyiahf/vczjk/g60;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-boolean v2, v0, Llyiahf/vczjk/g60;->OooOOO:Z

    iget-boolean v3, v0, Llyiahf/vczjk/g60;->OooOOOO:Z

    iget-boolean v4, v0, Llyiahf/vczjk/g60;->OooOOOo:Z

    iget-boolean v5, v0, Llyiahf/vczjk/g60;->OooOOo0:Z

    iget-object v6, v0, Llyiahf/vczjk/g60;->OooOOo:Llyiahf/vczjk/le3;

    iget-object v7, v0, Llyiahf/vczjk/g60;->OooOOoo:Llyiahf/vczjk/le3;

    iget-object v8, v0, Llyiahf/vczjk/g60;->OooOo00:Ljava/util/List;

    iget-object v9, v0, Llyiahf/vczjk/g60;->OooOo0:Llyiahf/vczjk/a91;

    iget-object v10, v0, Llyiahf/vczjk/g60;->OooOo0O:Llyiahf/vczjk/a91;

    invoke-static/range {v1 .. v15}, Llyiahf/vczjk/qqa;->OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Ljava/util/List;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

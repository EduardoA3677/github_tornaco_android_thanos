.class public final synthetic Llyiahf/vczjk/x45;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:Lgithub/tornaco/thanos/android/module/profile/LogActivity;

.field public final synthetic OooOOOO:Llyiahf/vczjk/dw4;

.field public final synthetic OooOOOo:Llyiahf/vczjk/j55;


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/android/module/profile/LogActivity;ZLlyiahf/vczjk/dw4;Llyiahf/vczjk/j55;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x45;->OooOOO0:Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    iput-boolean p2, p0, Llyiahf/vczjk/x45;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/x45;->OooOOOO:Llyiahf/vczjk/dw4;

    iput-object p4, p0, Llyiahf/vczjk/x45;->OooOOOo:Llyiahf/vczjk/j55;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p1, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    const/16 p1, 0x1001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v2, p0, Llyiahf/vczjk/x45;->OooOOOO:Llyiahf/vczjk/dw4;

    iget-object v3, p0, Llyiahf/vczjk/x45;->OooOOOo:Llyiahf/vczjk/j55;

    iget-object v0, p0, Llyiahf/vczjk/x45;->OooOOO0:Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    iget-boolean v1, p0, Llyiahf/vczjk/x45;->OooOOO:Z

    invoke-virtual/range {v0 .. v5}, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OooOoo(ZLlyiahf/vczjk/dw4;Llyiahf/vczjk/j55;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

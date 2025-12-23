.class public final synthetic Llyiahf/vczjk/z06;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:I

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;Llyiahf/vczjk/qs5;Ljava/lang/String;III)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z06;->OooOOO0:Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    iput-object p2, p0, Llyiahf/vczjk/z06;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/z06;->OooOOOO:Ljava/lang/String;

    iput p4, p0, Llyiahf/vczjk/z06;->OooOOOo:I

    iput p5, p0, Llyiahf/vczjk/z06;->OooOOo0:I

    iput p6, p0, Llyiahf/vczjk/z06;->OooOOo:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p1, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;->OoooO0O:I

    iget p1, p0, Llyiahf/vczjk/z06;->OooOOo:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v6

    iget-object v1, p0, Llyiahf/vczjk/z06;->OooOOO:Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/z06;->OooOOOO:Ljava/lang/String;

    iget v3, p0, Llyiahf/vczjk/z06;->OooOOOo:I

    iget v4, p0, Llyiahf/vczjk/z06;->OooOOo0:I

    iget-object v0, p0, Llyiahf/vczjk/z06;->OooOOO0:Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-virtual/range {v0 .. v6}, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;->OooOoo(Llyiahf/vczjk/qs5;Ljava/lang/String;IILlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

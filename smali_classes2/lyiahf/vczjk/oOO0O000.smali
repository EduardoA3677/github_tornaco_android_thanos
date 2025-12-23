.class public final synthetic Llyiahf/vczjk/oOO0O000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a;

.field public final synthetic OooOOOO:Landroid/content/pm/ApplicationInfo;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:Ljava/lang/String;

.field public final synthetic OooOOo0:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a;Ljava/lang/String;Landroid/content/pm/ApplicationInfo;ILjava/lang/String;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOO0O000;->OooOOO0:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oOO0O000;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/oOO0O000;->OooOOOO:Landroid/content/pm/ApplicationInfo;

    iput p4, p0, Llyiahf/vczjk/oOO0O000;->OooOOOo:I

    iput-object p5, p0, Llyiahf/vczjk/oOO0O000;->OooOOo0:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/oOO0O000;->OooOOo:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/oOO0O000;->OooOOO0:Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOO0O000;->OooOOOO:Landroid/content/pm/ApplicationInfo;

    iget-object v2, v1, Landroid/content/pm/ApplicationInfo;->packageName:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/oOO0O000;->OooOOo0:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/oOO0O000;->OooOOo:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/oOO0O000;->OooOOO:Ljava/lang/String;

    iget v5, p0, Llyiahf/vczjk/oOO0O000;->OooOOOo:I

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/a;->OooOoO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

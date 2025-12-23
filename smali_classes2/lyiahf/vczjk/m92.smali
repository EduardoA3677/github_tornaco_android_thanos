.class public abstract Llyiahf/vczjk/m92;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/oOOO0OO0;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/m92;->OooO00o:Llyiahf/vczjk/sc9;

    return-void
.end method

.method public static final OooO00o(Lgithub/tornaco/android/thanos/support/subscribe/code/DeviceCodeBinding;)Llyiahf/vczjk/br7;
    .locals 9

    sget-object v0, Llyiahf/vczjk/m92;->OooO00o:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nk3;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    const-string v0, "toJson(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/uf5;->OooO0Oo:Ljava/util/regex/Pattern;

    const-string v0, "application/json; charset=utf-8"

    const/4 v1, 0x0

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-object v0, v1

    :goto_0
    sget-object v2, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    if-eqz v0, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/uf5;->OooO00o(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    move-result-object v3

    if-nez v3, :cond_0

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "; charset=utf-8"

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v3, "<this>"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_1
    invoke-static {v0}, Llyiahf/vczjk/zsa;->OoooO00(Ljava/lang/String;)Llyiahf/vczjk/uf5;

    move-result-object v1
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    :catch_1
    move-object v0, v1

    goto :goto_1

    :cond_0
    move-object v2, v3

    :cond_1
    :goto_1
    invoke-virtual {p0, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object p0

    const-string v1, "this as java.lang.String).getBytes(charset)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v1, p0

    array-length v2, p0

    int-to-long v3, v2

    const/4 v2, 0x0

    int-to-long v5, v2

    int-to-long v7, v1

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/kba;->OooO0O0(JJJ)V

    new-instance v2, Llyiahf/vczjk/br7;

    invoke-direct {v2, v0, v1, p0}, Llyiahf/vczjk/br7;-><init>(Llyiahf/vczjk/uf5;I[B)V

    return-object v2
.end method
